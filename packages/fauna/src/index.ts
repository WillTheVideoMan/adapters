import faunadb from "faunadb"
import type * as Fauna from "faunadb"
import { createHash, randomBytes } from "crypto"
import type { Adapter } from "next-auth/adapters"

interface FaunaTime {
  value: string
}
interface User {
  id: string
  emailVerified: Date | null
  name?: string
  email?: string
  image?: string
}

interface Profile extends User {
  sub?: string
}
interface Session {
  id: string
  userId: string
  expires: Date
  sessionToken: string
  accessToken: string
}

interface VerificationRequest {
  id: string
  identifier: string
  token: string
  expires: Date
}

interface FaunaUser {
  ref: string | null
  data:
    | (Omit<User, "emailVerified"> & { emailVerified: FaunaTime | null })
    | null
}

interface FaunaSession {
  ref: string | null
  data: (Omit<Session, "expires"> & { expires: FaunaTime }) | null
}

interface FaunaVerificationRequest {
  ref: string | null
  data: (Omit<VerificationRequest, "expires"> & { expires: FaunaTime }) | null
}

export const FaunaAdapter: Adapter<
  Fauna.Client,
  never,
  User,
  Profile,
  Session
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

  const fqlTemplates = {
    doOnRef: (collection: string, ref: Fauna.ExprArg, fql: Fauna.Expr) =>
      Let(
        {
          /**
           */
          ref: Ref(Collection(collection), ref),
        },
        /**
         */
        If(Exists(Var("ref")), fql, { ref: null, data: null })
      ),
    doOnIndex: (index: string, terms: string[], fql: Fauna.Expr) =>
      Let(
        {
          /**
           */
          set: Match(Index(index), terms),
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
            If(Exists(Var("ref")), fql, {
              ref: null,
              data: null,
            })
          ),
          { ref: null, data: null }
        )
      ),
  }

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

  const dateToFaunaTimeOrNull = (date: Date | null) =>
    date ? Time(date.toISOString()) : null

  const faunaTimeToDateOrNull = (faunaTime: FaunaTime | null) =>
    faunaTime ? new Date(faunaTime.value) : null

  const reshape = {
    user: ({ ref, data: user }: FaunaUser): User => ({
      ...user,
      id: ref,
      emailVerified: faunaTimeToDateOrNull(user.emailVerified),
    }),
    session: ({ ref, data: session }: FaunaSession): Session => ({
      ...session,
      id: ref,
      expires: faunaTimeToDateOrNull(session.expires),
    }),
    verificationRequest: ({
      ref,
      data: verificationRequest,
    }: FaunaVerificationRequest): VerificationRequest => ({
      ...verificationRequest,
      id: ref,
      expires: faunaTimeToDateOrNull(verificationRequest.expires),
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
          const result = await fauna.query<FaunaUserResult>(
            Create(Collection(collections.User), {
              data: {
                name: profile.name,
                email: profile.email,
                image: profile.image,
                emailVerified: dateToFaunaTimeOrNull(profile.emailVerified),
              },
            })
          )

          if (!result.ref || !result.data) return null

          return reshape.user(result)
        },

        async getUser(id) {
          const result = await fauna.query<FaunaUserResult>(
            fqlTemplates.doOnRef(collections.User, id, Get(Var("ref")))
          )

          if (!result.ref || !result.data) return null

          return reshape.user(result)
        },

        async getUserByEmail(email) {
          if (!email) return null

          const result = await fauna.query<FaunaUserResult>(
            fqlTemplates.doOnIndex(indices.User, [email], Get(Var("ref")))
          )

          if (!result.ref || !result.data) return null

          return reshape.user(result)
        },

        async getUserByProviderAccountId(providerId, providerAccountId) {
          const result = await fauna.query<FaunaUserResult>(
            fqlTemplates.doOnIndex(
              indices.Account,
              [providerId, providerAccountId],
              fqlTemplates.doOnRef(
                indices.User,
                Select(["data", "userId"], Get(Var("ref"))),
                Get(Var("ref"))
              )
            )
          )

          if (!result.ref || !result.data) return null

          return reshape.user(result)
        },

        async updateUser(user) {
          const result = await fauna.query<FaunaUserResult>(
            fqlTemplates.doOnRef(
              collections.User,
              user.id,
              Update(Var("ref"), {
                data: {
                  name: user.name,
                  email: user.email,
                  image: user.image,
                  emailVerified: dateToFaunaTimeOrNull(user.emailVerified),
                },
              })
            )
          )

          if (!result.ref || !result.data) return null

          return reshape.user(result)
        },

        async deleteUser(userId) {
          await fauna.query<FaunaUserResult>(
            fqlTemplates.doOnRef(collections.User, userId, Delete(Var("ref")))
          )
          return null
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
          await fauna.query<FaunaResult>(
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

          return null
        },

        async unlinkAccount(_, providerId, providerAccountId) {
          await fauna.query<FaunaResult>(
            fqlTemplates.doOnIndex(
              indices.Account,
              [providerId, providerAccountId],
              Delete(Var("ref"))
            )
          )

          return null
        },

        async createSession(user) {
          const result = await fauna.query<FaunaSessionResult>(
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

          if (!result.ref || !result.data) return null

          return reshape.session(result)
        },

        async getSession(sessionToken) {
          const result = await fauna.query<FaunaSessionResult>(
            fqlTemplates.doOnIndex(
              indices.Session,
              [sessionToken],
              Get(Var("ref"))
            )
          )

          if (!result.ref || !result.data) return null

          if (new Date(result.data.expires.value) < new Date()) {
            await fauna.query<FaunaSessionResult>(
              fqlTemplates.doOnRef(
                collections.Session,
                result.ref,
                Delete(Var("ref"))
              )
            )

            return null
          }

          return reshape.session(result)
        },

        async updateSession(session, force) {
          if (
            !force &&
            Number(session.expires) - sessionMaxAgeMs + sessionUpdateAgeMs >
              Date.now()
          ) {
            return null
          }

          const result = await fauna.query<FaunaSessionResult>(
            fqlTemplates.doOnRef(
              collections.User,
              session.id,
              Update(Var("ref"), {
                data: {
                  expires: dateToFaunaTimeOrNull(
                    new Date(Date.now() + sessionMaxAgeMs)
                  ),
                },
              })
            )
          )

          if (!result.ref || !result.data) return null

          return reshape.session(result)
        },

        async deleteSession(sessionToken) {
          await fauna.query<FaunaSessionResult>(
            fqlTemplates.doOnIndex(
              indices.Session,
              [sessionToken],
              Delete(Var("ref"))
            )
          )
          return null
        },

        async createVerificationRequest(identifier, url, token, _, provider) {
          await fauna.query<FaunaVerificationRequestResult>(
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

          return null
        },

        async getVerificationRequest(identifier, token) {
          const hashedToken = hashToken(token)

          const result = await fauna.query<FaunaVerificationRequestResult>(
            fqlTemplates.doOnIndex(
              indices.VerificationRequest,
              [identifier, hashedToken],
              Get(Var("ref"))
            )
          )

          if (!result.ref || !result.data) return null

          if (new Date(result.data.expires.value) < new Date()) {
            await fauna.query<FaunaVerificationRequestResult>(
              fqlTemplates.doOnRef(
                collections.VerificationRequest,
                result.ref,
                Delete(Var("ref"))
              )
            )
            return null
          }

          return reshape.session(result)
        },

        async deleteVerificationRequest(identifier, token) {
          await fauna.query<FaunaVerificationRequestResult>(
            fqlTemplates.doOnIndex(
              indices.VerificationRequest,
              [identifier, hashToken(token)],
              Delete(Var("ref"))
            )
          )

          return null
        },
      }
    },
  }
}
