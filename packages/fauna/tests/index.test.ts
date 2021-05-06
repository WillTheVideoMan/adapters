import faunadb from "faunadb"
//  import type * as Fauna from "faunadb"
import { FaunaAdapter } from "../src"
import type { AppOptions } from "next-auth/internals"
import type { User } from "next-auth"
import Providers from "next-auth/providers"

const faunaClient = new faunadb.Client()
const faunaAdapter = FaunaAdapter(faunaClient)

interface Session {
  id: string
  userId: string
  expires: Date
  sessionToken: string
  accessToken: string
}

interface VerificationRequest {
  identifier: string
  token: string
  expires: Date
}

let session: Session | null = null
let user:
  | (User & {
      id: string
      emailVerified?: Date
    })
  | null = null
let verificationRequest: VerificationRequest | null = null

const SECRET = "secret"
const TOKEN = "secret"

const appOptions: AppOptions = {
  action: "signin",
  basePath: "",
  baseUrl: "",
  callbacks: {},
  cookies: {},
  debug: false,
  events: {},
  jwt: {},
  theme: "auto",
  logger: {
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  } as const,
  pages: {},
  providers: [],
  secret: "",
  session: {
    jwt: false,
    maxAge: 60 * 60 * 24 * 30,
    updateAge: 60 * 60 * 24,
  },
  adapter: faunaAdapter as any,
}

const sendVerificationRequestMock = jest.fn()

const emailProvider = {
  ...Providers.Email({
    sendVerificationRequest: sendVerificationRequestMock,
  }),
} as any

describe("adapter functions", () => {
  // User
  test("createUser", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)

    user = await adapter.createUser({
      email: "test@next-auth.com",
      name: "test",
      image: "https://",
    } as any)

    expect(user.email).toMatchInlineSnapshot(`"test@next-auth.com"`)
    expect(user.name).toMatchInlineSnapshot(`"test"`)
    expect(user.image).toMatchInlineSnapshot(`"https://"`)
  })
  test("updateUser", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!user) throw new Error("No User Available")

    user = await adapter.updateUser({
      id: user.id,
      name: "Changed",
    } as any)
    expect(user?.name).toEqual("Changed")
  })
  // Sessions
  test("createSession", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!user) throw new Error("No User Available")
    session = await adapter.createSession({
      id: user.id,
    } as any)

    expect(session.sessionToken.length).toMatchInlineSnapshot(`64`)
    expect(session.accessToken.length).toMatchInlineSnapshot(`64`)
  })

  test("getSession", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!session) throw new Error("No Session Available")

    const result = await adapter.getSession(session.sessionToken)

    expect(result?.sessionToken).toEqual(session.sessionToken)
    expect(result?.accessToken).toEqual(session.accessToken)
  })
  test("updateSession", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!session) throw new Error("No Session Available")

    const expires = new Date(2070, 1)
    session = await adapter.updateSession(
      {
        accessToken: "e.e.e",
        userId: "userId",
        expires,
        id: session.id,
        sessionToken: session.sessionToken,
      },
      true
    )
    if (!session) throw new Error("No Session Updated")

    // Using default maxAge, which is 30 days
    const thirtyDaysFromNow = new Date()
    thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30)
    expect(
      Math.abs(session.expires.getTime() - thirtyDaysFromNow.getTime())
    ).toBeLessThan(1000)
  })

  test("deleteSession", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!session) throw new Error("No Session Available")
    const result = await adapter.deleteSession(session.sessionToken)
    expect(result?.sessionToken).toEqual(session.sessionToken)
  })
  // VerificationRequests
  test("createVerificationRequest", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    const identifier = "any"
    const result = await adapter.createVerificationRequest?.(
      identifier,
      "https://some.where",
      TOKEN,
      SECRET,
      emailProvider
    )
    verificationRequest = result?.[0]
    expect(verificationRequest.identifier).toEqual(identifier)
    expect(sendVerificationRequestMock).toBeCalledTimes(1)
  })
  test("getVerificationRequest", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!verificationRequest)
      throw new Error("No Verification Request Available")

    const result = await adapter.getVerificationRequest?.(
      verificationRequest.identifier,
      TOKEN,
      SECRET,
      emailProvider
    )
    expect(result?.token).toEqual(verificationRequest.token)
  })
  test("deleteVerificationRequest", async () => {
    const adapter = await faunaAdapter.getAdapter(appOptions)
    if (!verificationRequest)
      throw new Error("No Verification Request Available")
    const result = await adapter.deleteVerificationRequest?.(
      verificationRequest.identifier,
      TOKEN,
      SECRET,
      emailProvider
    )
    expect(result?.identifier).toEqual(verificationRequest.identifier)
  })
})
