import faunadb from "faunadb"
import type * as Fauna from "faunadb"
import { createHash, randomBytes } from "crypto"
import type { User, Profile } from "next-auth"
import type { Adapter } from "next-auth/adapters"

/**
 * Define Session interface here since the built-in next-auth Session interface
 * refers more closely to the client-side types than the server-side ones.
 *
 * ['DefaultSession'](https://github.com/nextauthjs/next-auth/blob/main/types/index.d.ts#L379)
 */
interface FaunaSession {
  id: string
  userId: string
  expires: Date
  sessionToken: string
  accessToken: string
}

interface FaunaResult {
  ref: string
  data: object
}

type FaunaResultOrNull = FaunaResult | { ref: null; data: null }

export const FaunaAdapter: Adapter<
  Fauna.Client,
  never,
  User & { id: string; emailVerified?: Date },
  Profile & { emailVerified?: Date },
  FaunaSession
> = (fauna) => {
  const {
    Create,
    Collection,
    Time,
    If,
    Exists,
    Match,
    Index,
    Get,
    Ref,
    Paginate,
    Delete,
    Select,
    Let,
    Var,
    Update,
  } = faunadb.query

  const collections = {
    User: "users",
    Account: "accounts",
    Session: "sessions",
    VerificationRequest: "verification_requests",
  }

  const indices = {
    Account: "account_by_provider_account_id",
    User: "user_by_email",
    Session: "session_by_token",
    VerificationRequest: "verification_request_by_token",
  }

  const dateToFaunaTimeOrNull = (date: Date | undefined) =>
    date ? Time(date.toISOString()) : null

  const faunaTimeToDateOrNull = (faunaTime: { value: string }) =>
    faunaTime ? new Date(faunaTime.value) : null

  const reshape = {
    user: (ref: string, user: object) => ({
      ...user,
      id: ref,
      emailVerified: faunaTimeToDateOrNull(user.emailVerified),
    }),
    account: (ref: string, account: object) => ({
      ...account,
      id: ref,
      accessTokenExpires: faunaTimeToDateOrNull(account.accessTokenExpires),
    }),
    session: (ref: string, session: object) => ({
      ...session,
      id: ref,
      expires: new Date(session.expires.value),
    }),
    verificationRequest: (ref: string, verificationRequest: object) => ({
      ...verificationRequest,
      id: ref,
      expires: faunaTimeToDateOrNull(verificationRequest.expires.value),
    }),
  }

  return {
    async getAdapter({ session, secret, ...appOptions }) {
      const sessionMaxAgeMs = session.maxAge * 1000 // default is 30 days
      const sessionUpdateAgeMs = session.updateAge * 1000 // default is 1 day

      /**
       * @todo Move this to core package
       * @todo Use bcrypt or a more secure method
       */
      const hashToken = (token: string) =>
        createHash("sha256").update(`${token}${secret}`).digest("hex")

      return {
        async createUser(profile) {
          const { ref, data: user } = await fauna.query<FaunaResult>(
            /**
             * Create a new user document within the users collection.
             * The user document is populated with data from the profile.
             */
            Create(Collection(collections.User), {
              data: {
                name: profile.name,
                email: profile.email,
                image: profile.image,
                emailVerified: dateToFaunaTimeOrNull(profile.emailVerified),
              },
            })
          )

          return reshape.user(ref, user)
        },

        async getUser(id) {
          const { ref, data: user } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `ref`, which holds a reference to the user's
                 * fauna document within the users collection.
                 *
                 * The passed user id was set to the value of the user's fauna document
                 * reference upon creation.
                 *
                 * In this way, the user id is used to retrieve the user's fauna document.
                 *
                 * (i.e. user's fauna document reference == user id)
                 */
                ref: Ref(Collection(collections.User), id),
              },
              /**
               * Then, if the reference points to a valid user document, get that document.
               * Else, return a nullish return object.
               */
              If(Exists(Var("ref")), Get(Var("ref")), { ref: null, data: null })
            )
          )

          if (!ref || !user) return null

          return reshape.user(ref, user)
        },

        async getUserByEmail(email) {
          /**
           * If no email is provided, then we cannot continue.
           * Hence, return null.
           */
          if (!email) return null

          const { ref, data: user } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `set` which holds a set of matches against
                 * the 'user_by_email' index.
                 *
                 * The passed in email is used as the search term.
                 */
                set: Match(Index(indices.User), email),
              },
              /**
               * Then, if a member of the set holds a reference to a valid user document, get that document.
               * Else, return a nullish return object.
               */
              If(Exists(Var("set")), Get(Var("set")), { ref: null, data: null })
            )
          )

          if (!ref || !user) return null

          return reshape.user(ref, user)
        },

        async getUserByProviderAccountId(providerId, providerAccountId) {
          const { ref, data: user } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `accountSet` which holds a set of matches against
                 * the 'account_by_provider_account_id' index.
                 *
                 * The passed in providerId and providerAccountId together form the search terms.
                 */
                accountSet: Match(Index(indices.Account), [
                  providerId,
                  providerAccountId,
                ]),
              },
              /**
               * Then, if a member of the set holds a reference to a valid account document, continue.
               * Else, return a nullish return object.
               */
              If(
                Exists(Var("accountSet")),
                Let(
                  {
                    /**
                     * Define a local fauna variable `userRef` which holds a document reference to
                     * the user's fauna document as determined by the 'userId' of the account document.
                     *
                     * Once again we rely on the fact that the user's fauna document reference
                     * equals the user's id.
                     */
                    userRef: Ref(
                      Collection("users"),
                      Select(["data", "userId"], Get(Var("accountSet")))
                    ),
                  },
                  /**
                   * Then, if the reference points to a valid user document, get that document.
                   * Else, return a nullish return object.
                   */
                  If(Exists(Var("userRef")), Get(Var("userRef")), {
                    ref: null,
                    data: null,
                  })
                ),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !user) return null

          return reshape.user(ref, user)
        },

        async updateUser(user) {
          const { ref, data: newUser } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `ref`, which holds a reference to the user's
                 * fauna document within the users collection.
                 */
                ref: Ref(Collection(collections.User), user.id),
              },
              /**
               * Then, if the reference points to a valid user document, update that document
               * to match the values of the passed in user object.
               * Else, return a nullish return object.
               */
              If(
                Exists(Var("ref")),
                Update(Var("ref"), {
                  data: {
                    name: user.name,
                    email: user.email,
                    image: user.image,
                    emailVerified: dateToFaunaTimeOrNull(user.emailVerified),
                  },
                }),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !newUser) return null

          return reshape.user(ref, newUser)
        },

        async deleteUser(userId) {
          const { ref, data: user } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `ref`, which holds a reference to the user's
                 * fauna document within the users collection.
                 */
                ref: Ref(Collection(collections.User), userId),
              },
              /**
               * Then, if the reference points to a valid user document, delete that document.
               * Else, return a nullish return object.
               */
              If(Exists(Var("ref")), Delete(Var("ref")), {
                ref: null,
                data: null,
              })
            )
          )

          if (!ref || !user) return null

          return reshape.user(ref, user)
        },

        async linkAccount(
          userId,
          providerId,
          providerType,
          providerAccountId,
          refreshToken,
          accessToken,
          accessTokenExpires
        ) {
          const { ref, data: account } = await fauna.query<FaunaResult>(
            /**
             * Create a new account document within the accounts collection.
             * The account document is populated with the passed in parameters.
             */
            Create(Collection(collections.Account), {
              data: {
                userId,
                providerId,
                providerType,
                providerAccountId,
                refreshToken,
                accessToken,
                accessTokenExpires: dateToFaunaTimeOrNull(accessTokenExpires),
              },
            })
          )

          return reshape.account(ref, account)
        },

        async unlinkAccount(_, providerId, providerAccountId) {
          const { ref, data: account } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `set` which holds a set of matches against
                 * the 'account_by_provider_account_id' index.
                 *
                 * The passed in providerId and providerAccountId together form the search terms.
                 */
                set: Match(Index(indices.Account), [
                  providerId,
                  providerAccountId,
                ]),
              },
              /**
               * Then, if a member of the set holds a reference to a valid account document, continue.
               * Else, return a nullish return object.
               */
              If(
                Exists(Var("set")),
                Let(
                  {
                    /**
                     * Define a local fauna variable `ref` which holds a reference to the account's
                     * fauna document.
                     *
                     * We select the first document reference within the index matches set.
                     */
                    ref: Select(0, Paginate(Var("set"))),
                  },
                  /**
                   * Then, if the reference points to a valid user document, delete that document.
                   * Else, return a nullish return object.
                   */
                  If(Exists(Var("ref")), Delete(Var("ref")), {
                    ref: null,
                    data: null,
                  })
                ),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !account) return null

          return reshape.account(ref, account)
        },

        async createSession(user) {
          const { ref, data: session } = await fauna.query<FaunaResult>(
            /**
             * Create a new session document within the sessions collection.
             * The session document is populated with the passed in parameters.
             *
             * The session is intrinsicly linked to the user who instantiated it
             * through linkage by `user.id`.
             */
            Create(Collection(collections.Session), {
              data: {
                userId: user.id,
                expires: dateToFaunaTimeOrNull(
                  new Date(Date.now() + sessionMaxAgeMs)
                ),
                sessionToken: randomBytes(32).toString("hex"),
                accessToken: randomBytes(32).toString("hex"),
              },
            })
          )

          return reshape.session(ref, session)
        },

        async getSession(sessionToken) {
          const { ref, data: session } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `set` which holds a set of matches against
                 * the 'session_by_token' index.
                 *
                 * The passed in sessionToken is used as the search term.
                 */
                set: Match(Index(indices.Session), sessionToken),
              },
              /**
               * Then, if a member of the set holds a reference to a valid session document, get that document.
               * Else, return a nullish return object.
               */
              If(Exists(Var("set")), Get(Var("set")), { ref: null, data: null })
            )
          )

          if (!ref || !session) return null

          /**
           * Verify that the session has not expired.
           * If expired, delete the related fauna session document and return null.
           *
           * Fauna returns Time as an object of shape: {value: ISOString}.
           * The `expires` property is returned as an object with this shape.
           * Hence, a new date is constructed with an ISOString derived from
           * the `expires` property's value.
           */
          if (new Date(session.expires.value) < new Date()) {
            await fauna.query<FaunaResultOrNull>(
              Let(
                {
                  /**
                   * Define a local fauna variable `ref`, which holds a reference to the session's
                   * fauna document within the sessions collection.
                   */
                  ref: Ref(Collection(collections), ref),
                },
                /**
                 * Then, if the reference points to a valid session document, delete that document.
                 * Else, return a nullish return object.
                 */
                If(Exists(Var("ref")), Delete(Var("ref")), {
                  ref: null,
                  data: null,
                })
              )
            )

            return null
          }

          return reshape.session(ref, session)
        },

        async updateSession(session, force) {
          if (
            !force &&
            Number(session.expires) - sessionMaxAgeMs + sessionUpdateAgeMs >
              Date.now()
          ) {
            return null
          }

          const {
            ref,
            data: newSession,
          } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `ref`, which holds a reference to the session's
                 * fauna document within the sessions collection.
                 *
                 * The session id is equal to the fauna document reference for that session document.
                 */
                ref: Ref(Collection(collections.Session), session.id),
              },
              /**
               * Then, if the reference points to a valid session document, update that document
               * data `expires` property to refresh the duration of the session.
               * Else, return a nullish return object.
               */
              If(
                Exists(Var("ref")),
                Update(Var("ref"), {
                  data: {
                    expires: dateToFaunaTimeOrNull(
                      new Date(Date.now() + sessionMaxAgeMs)
                    ),
                  },
                }),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !newSession) return null

          return reshape.session(ref, newSession)
        },

        async deleteSession(sessionToken) {
          const { ref, data: session } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 * Define a local fauna variable `set` which holds a set of matches against
                 * the 'session_by_token' index.
                 *
                 * The passed in sessionToken forms the search terms.
                 */
                set: Match(Index(indices.Session), sessionToken),
              },
              /**
               * Then, if a member of the set holds a reference to a valid session document, continue.
               * Else, return a nullish return object.
               */
              If(
                Exists(Var("set")),
                Let(
                  {
                    /**
                     * Define a local fauna variable `ref` which holds a reference to the session's
                     * fauna document.
                     *
                     * We select the first document reference within the index matches set.
                     */
                    ref: Select(0, Paginate(Var("set"))),
                  },
                  /**
                   * Then, if the reference points to a valid session document, delete that document.
                   * Else, return a nullish return object.
                   */
                  If(Exists(Var("ref")), Delete(Var("ref")), {
                    ref: null,
                    data: null,
                  })
                ),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !session) return null

          return reshape.account(ref, session)
        },

        async createVerificationRequest(identifier, url, token, _, provider) {
          const {
            ref,
            data: verificationRequest,
          } = await fauna.query<FaunaResult>(
            /**
             * Create a new verification request document within the verification_requests collection.
             * The verification request document is populated with the passed in parameters.
             */
            Create(Collection(collections.VerificationRequest), {
              data: {
                identifier,
                token: hashToken(token),
                expires: dateToFaunaTimeOrNull(
                  new Date(Date.now() + provider.maxAge * 1000)
                ),
              },
            })
          )

          await provider.sendVerificationRequest({
            identifier,
            url,
            token,
            baseUrl: appOptions.baseUrl,
            provider,
          })

          return reshape.verificationRequest(ref, verificationRequest)
        },

        async getVerificationRequest(identifier, token) {
          const hashedToken = hashToken(token)

          const {
            ref,
            data: verificationRequest,
          } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 */
                set: Match(Index(indices.VerificationRequest), [
                  identifier,
                  hashedToken,
                ]),
              },
              /**
               */
              If(Exists(Var("set")), Get(Var("set")), { ref: null, data: null })
            )
          )

          if (!ref || !verificationRequest) return null

          /**
           */
          if (new Date(verificationRequest.expires.value) < new Date()) {
            await fauna.query<FaunaResultOrNull>(
              Let(
                {
                  /**
                   */
                  set: Match(Index(indices.VerificationRequest), [
                    identifier,
                    hashedToken,
                  ]),
                },
                /**
                 */
                If(
                  Exists(Var("set")),
                  Let(
                    {
                      /**
                       */
                      ref: Select(0, Paginate(Var("set"))),
                    },
                    /**
                     */
                    If(Exists(Var("ref")), Delete(Var("ref")), {
                      ref: null,
                      data: null,
                    })
                  ),
                  { ref: null, data: null }
                )
              )
            )

            return null
          }

          return reshape.session(ref, session)
        },

        async deleteVerificationRequest(identifier, token) {
          const { ref, data: session } = await fauna.query<FaunaResultOrNull>(
            Let(
              {
                /**
                 */
                set: Match(Index(indices.VerificationRequest), [
                  identifier,
                  hashToken(token),
                ]),
              },
              /**
               */
              If(
                Exists(Var("set")),
                Let(
                  {
                    /**
                     */
                    ref: Select(0, Paginate(Var("set"))),
                  },
                  /**
                   */
                  If(Exists(Var("ref")), Delete(Var("ref")), {
                    ref: null,
                    data: null,
                  })
                ),
                { ref: null, data: null }
              )
            )
          )

          if (!ref || !session) return null

          return reshape.account(ref, session)
        },
      }
    },
  }
}
