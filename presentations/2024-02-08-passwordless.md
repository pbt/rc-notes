# passwordless and webauthn: part 1

**P.B. To**

The Recurse Center

2024-02-08 

in today's talk we will cover the basic mechanisms of passkey
authentication and the underlying FIDO protocol. if time permits we might cover
how to implement passkey authentication.

## motivation

### 1: we suck at remembering passwords

we have a lot of things to remember, and we tend to not remember passwords, especially ones we don't 
use often.[^nih]

we tend to reuse passwords, despite efforts to discourage 
this practice.[^patient]

[^nih]: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3515440/
[^patient]: https://www.cs.dartmouth.edu/~sws/pubs/ksbk15-draft.pdf

### 2: we can't trust websites to invest enough in security
we can't rely on our websites to secure our passwords either. account leaks are
commonplace; your password has probably already been stolen.[^hibp] attackers know we reuse our
passwords because they are also human. so they use these compromised credentials in automated
credential stuffing attacks.[^cred] 

[^hibp]: https://haveibeenpwned.com
[^cred]: https://www.cloudflare.com/learning/bots/what-is-credential-stuffing/

### 3: existing solutions leave a lot to be desired
we could use a **password manager**, but that just shifts responsibility to the creators of
password managers. and some of them are really not so good. (**PSA: don't use LastPass**[^last] [^palant])

**two-factor authentication** exists, but it is often confusing to set up. SMS-based authentication
is not so secure because cellphone providers are susecptible to [SIM swap attacks](https://en.wikipedia.org/wiki/SIM_swap_scam)
and you might not want to give your phone number to a website (if they can barely keep your password
secure, what chance does your phone number have?) [TOTP authentication](https://en.wikipedia.org/wiki/Time-based_one-time_password)
is better, but authenticator apps are kind of a pain. password managers will now store these two-factor
auth codes for you, but i'm kind of nervous about password managers already! (see the LastPass hack.)

**magic links, openID connect, etc.** essentially shift the security burden onto another third party
provider (an email provider, google, github, etc.) while google and github have never suffered a
security breach, attackers have exfiltrated non-password but personally identifiable information from
meta[^meta].

**SSH key authentication** is cumbersome to set up. (more on this later though.)

[^last]: https://krebsonsecurity.com/2023/09/experts-fear-crooks-are-cracking-keys-stolen-in-lastpass-breach/
[^meta]: https://www.bleepingcomputer.com/news/security/533-million-facebook-users-phone-numbers-leaked-on-hacker-forum/

### 4: passwords just kinda suck
if a password gets leaked, it's just kind of out there. anyone can just... use them. surely there
must be a better way?

### 5: attackers are getting better
technology has advanced, and attackers have become more motivated. as a result, phishing attacks have 
become highly sophisticated[^doctorow] and more convincing[^deepfake].
according to IBM, in 2023, phishing was the most common and most successful way for hackers to 
gain unauthorized account access.[^ibm] 

[^deepfake]: https://www.cnn.com/2024/02/04/asia/deepfake-cfo-scam-hong-kong-intl-hnk/index.html
[^doctorow]: https://pluralistic.net/2024/02/05/cyber-dunning-kruger/
[^ibm]: https://www.ibm.com/downloads/cas/DB4GL8YM

## enter the passkey
[passkeys](https://passkeys.dev) are a "passwordless" (more on that later) authentication mechanism, 
designed to replace the need for a human or computer to remember passwords. in a press release
in 2023, google called passkeys the "beginning of the end of the password":

>an easier and more secure alternative to passwords...  passkeys let users sign in to apps and sites the same way they unlock their devices: with a fingerprint, a face scan or a screen lock PIN. And, unlike passwords, passkeys are resistant to online attacks like phishing [^goog]

[^goog]: https://blog.google/technology/safety-security/the-beginning-of-the-end-of-the-password/


passkeys are part of an overall authentication and verification solution called FIDO.[^fidoproto]

[^fidoproto]: https://medium.com/webauthnworks/introduction-to-webauthn-api-5fd1fb46c285


### there's a lot of money and a lot of big names behind FIDO
passkeys/FIDO are being developed by the FIDO Alliance, which counts many
major tech companies, banks, health providers, and governments among its membership.[^fido]

[^fido]: https://fidoalliance.org/members/

### dramatis personae
1. the **relying party** (server): a website that is trying to **authenticate** and **verify**
who has access to information. 
2. the **client**: a web browser or app that is trying to receive this information. relays information
between the relying party and the authenticator.
3. the **authenticator**: holds the passkeys and prompts the user to verify themselves. this
can be done in software or in hardware (a phone or a laptop's secure enclave)

### the passkey creation process
#### a passkey is "just" a public/private key pair

we have already seen passkeys in the form of SSH keys:
[tutorial: SSH keys on GitHub](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent)

in SSH private key auth, the following is done:
1. first, a private/public keypair is generated
2. the public key is copied over to the server
3. when you sign in, the server generates a cryptographic challenge using the public key, which can
only be solved if you possess the private key.
4. if you possess the private key, you can successfully reply to the challenge. the server knows you
have the private key and then you are *authenticated.*

(for this talk, *how* private-key encryption works
is out of scope; check out this [youtube video](https://www.youtube.com/watch?v=YEBfamv-_do))

that sounds great. but, there's a ways to go, 
especially considering how people sign into
websites in reality.

1. what if you needed to log in from another website? you don't want
to sync the private keys in an insecure fashion; that would defeat
the point!
2. you need to secure the private keys somehow, because if they
*are* leaked, they put you in as much risk as passwords!!
3. likewise, you might be tempted to upload the same public key
to every server you visit. if your private key ever leaks, that
would put you at huge risk.
4. what about replay attacks? or phishing? someone could convince
you to sign a challenge onto a domain they control
and then simply replay that attack against the real domain.

passkeys solve these problems by creating a standard for key management:

#### passkeys are designed to be shared securely
the creators of passkeys anticipated that you would sign onto an account from multiple locations.
so they created a way for you to store passkeys on your phone and through the use of a one-time QR code,
securely perform the passkey authentication from your phone to any computer, without the secrets
ever leaving your device.

#### passkeys rely on a platform authenticator
for example, your iphone has a secure enclave
that uses a short PIN, fingerprint, or facial recognition to unlock itself. this same technology
is used to secure your passkeys. or you can buy a hardware key.

*software* authenticators are also supported. 1password is 
a software authenticator for passkeys, so you don't have to use
the one built into your device.

#### passkeys are unique to each website
this is enforced through a variety of mechanisms we will see in the
demo

#### passkeys can only be shared through HTTPS
this helps prevent replay attacks and phishing

## if authenticated data you wish to see, first you must solve my <s>riddles</s>cryptographic challenges three
#### demo 1: inspecting assertions
we will use this demo website (https://webauthn.io) 

as well as a debugger (https://webauthn.passwordless.id/demos/playground.html)

#### registration
first, i type in a username.

the browser sends this request:
<details>

```json
{"username":"orpheus","user_verification":"preferred","attestation":"none","attachment":"all","algorithms":["es256","rs256"],"discoverable_credential":"preferred","hints":[]}
```
</details>

the server responds with an **ID**, a **Challenge**, and other
parameters for e.g. generating public keys or types of authenticators:

<details>

```json
{
    "rp": {
        "name": "webauthn.io",
        "id": "webauthn.io"
    },
    "user": {
        "id": "b3JwaGV1cw",
        "name": "orpheus",
        "displayName": "orpheus"
    },
    "challenge": "-i6vNfKQb6Y6kXRzru6MK_Y0QyecB2x7tsAAS3pyd8_Nw4-bYtbv7tfYLF7VZ7McN5p6zyR6XSVmnD2s6XF52w",
    "pubKeyCredParams": [
        {
            "type": "public-key",
            "alg": -7
        },
        {
            "type": "public-key",
            "alg": -257
        }
    ],
    "timeout": 60000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "preferred",
        "requireResidentKey": false,
        "userVerification": "preferred"
    },
    "attestation": "none",
    "hints": [],
    "extensions": {
        "credProps": true
    }
}
```
</details>

at this point, the authenticator takes over. it creates a private key and
securely stores it away, verifying the user first.

it then sends a response to this registration challenge:

- the **clientDataJSON** is returned from the authenticator itself.
- inspecting the JSON and decoding the JWT will reveal that it has the challenge.
- the **attestationObject** contains the public key, encoded in CBOR format.
<details>

```json
{
  "username": "orpheus",
  "response": {
    "id": "bzd33H7oHzfcHmpuMpZZydIs0xs",
    "rawId": "bzd33H7oHzfcHmpuMpZZydIs0xs",
    "response": {
      "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBdAAAAAPv8MAcVTk7MjAtuAgVX170AFG83d9x-6B833B5qbjKWWcnSLNMbpQECAyYgASFYICySw2RwPHI-iwTdExE7cuWqS5TD_I5y5LyPVvLFKAdWIlgg71eT5mhLXgDLp5RdjWPFimU4bZCM6apTpV5aH6n_P5E",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiLWk2dk5mS1FiNlk2a1hSenJ1Nk1LX1kwUXllY0IyeDd0c0FBUzNweWQ4X053NC1iWXRidjd0ZllMRjdWWjdNY041cDZ6eVI2WFNWbW5EMnM2WEY1MnciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
      "transports": [
        "hybrid",
        "internal"
      ],
      "publicKeyAlgorithm": -7,
      "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELJLDZHA8cj6LBN0TETty5apLlMP8jnLkvI9W8sUoB1bvV5PmaEteAMunlF2NY8WKZThtkIzpqlOlXlofqf8_kQ",
      "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBdAAAAAPv8MAcVTk7MjAtuAgVX170AFG83d9x-6B833B5qbjKWWcnSLNMbpQECAyYgASFYICySw2RwPHI-iwTdExE7cuWqS5TD_I5y5LyPVvLFKAdWIlgg71eT5mhLXgDLp5RdjWPFimU4bZCM6apTpV5aH6n_P5E"
    },
    "type": "public-key",
    "clientExtensionResults": {
      "credProps": {
        "rk": true
      }
    },
    "authenticatorAttachment": "cross-platform"
  }
}
```
</details>

when we authenticate, we get authentication options:

note again the **challenge**, and **allowCredentials**: this is the way
that the client can match what credential it will provide. 

note the **rpId** and that it is equivalent to the domain. if it's not,
the client will refuse to authenticate.

<details>

```json
{
  "rpIdHash": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA=",
  "flags": {
    "userPresent": true,
    "userVerified": true,
    "backupEligibility": true,
    "backupState": true,
    "attestedData": false,
    "extensionsIncluded": false
  },
  "counter": 0
}
```
</details>

we respond with the following:

<details>

```json
{
  "username": "orpheus",
  "response": {
    "id": "bzd33H7oHzfcHmpuMpZZydIs0xs",
    "rawId": "bzd33H7oHzfcHmpuMpZZydIs0xs",
    "response": {
      "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAdAAAAAA",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVI5SnVoajVfZDM5Wmk2SG93RWk3V24tZHpkTGc5UXBxblNqWTNpWlY2Q2E3S0UyWlJpOHlaMU0tR1JXZ21wMHdZcXpnTHM5SXU2Z3JoaWs1VGxyaVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIn0",
      "signature": "MEUCIQD13QWDskSGYHzz77xUrEDiUUacledE7JTVYnT_xF1MaAIgeSS0WRHJ11kWtb6_7l7Y3PU2NQsGXlNG84XrSN3PN78",
      "userHandle": "b3JwaGV1cw"
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "platform"
  }
}
```
</details>

the clientIdJson contains the challenge again. the signature 
was signed with the private key and will be compared with the
public key on the server.

if the server accepts this challenge, it returns something like:

<details>

```json
{
    "data": {
        "device": {
            "name": "macOS computer",
            "type": "unknown"
        },
        "deviceId": "41d06f0c-c9c8-4699-a463-aabfc2dca62c",
        "displayName": "orpheus",
        "username": "orpheus",
        "uuid": "56180ead-63da-4743-84ba-3593ac354dea"
    },
    "status": "success"
}
```
</details>

### more notes

#### the authenticator requires two types of verification
the authenticator, at this point, will verify require a user to:
- verify presence (a 
Yubikey button press, unlocked phone)
- verify themselves (a biometric, a short PIN)

#### to prevent MITM attacks: passkeys can only be shared in a secure context
a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) is
either a local computer (e.g. `http://localhost`) or an HTTPS endpoint. this is mandated to prevent
MITM (person-in-the-middle) attacks.

#### to prevent replay attacks: `authenticatorData` is unique and there is a timeout
the authentication data is a base64 representation of a custom binary encoding.
(see here: https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data)

here's what it looks like decoded:

<details>

```json
{
  "rpIdHash": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA=",
  "flags": {
    "userPresent": true,
    "userVerified": true,
    "backupEligibility": true,
    "backupState": true,
    "attestedData": false,
    "extensionsIncluded": false
  },
  "counter": 0
}
```
</details>

notice the `counter` here. this gets incremented by the authenticator
each time a login is attempted. that way we can prevent a replay attack.

#### to prevent phishing: `rpId` must match the URL and HTTPS is required

HTTPS ensures that the server owns the domain, and comparing the `rpId` ensures
that the browser sends only the credentials for that website and 
nothing else.

## discussion

### wow. that's complicated
uhhh yeah. it's much more complicated than standard password auth. there are
a few libraries available but this is all relatively new, and you need
to implement [this entire spec](https://www.w3.org/TR/webauthn-2/) 
to ensure that passkey authentication is resistant toward MITM,
replay, or phishing attacks.

### is syncing credentials good?
>In fact, Apple requires you to enable iCloud and iCloud Keychain in order to save a passkey on a macOS or iOS device.
>...
> iCloud is insecure. Apple makes it too easy for criminals to "recover" your Apple ID and seemingly impossible for you to lock down your account voluntarily

both apple and google encourage you to use syncing, and
google touts this as an advantage to using passkeys![^goog] but
what if these sync services get compromised? 

one response to that is that even if they
do, a passkey is relatively easy to revoke and because they 
are enforced to be unique, you can more easily roll the passkeys,
in case of any sort of compromise. and the attack surface is much
lower. on the other hand, it shifts entirely toward a single
point of failure.

### software passkey managers make me a bit nervous
we saw that lastpass got breached and has barely acknowledged the problem[^palant]. 
there's nothing stopping a company with poor security practices from also implementing passkeys. 

on the other hand, they're necessary for passkey portability, to make
sure that google and apple aren't the only ways to manage your passkeys.

### is a PIN or biometrics more secure than a password?
in my demo, i authenticated via my iphone, using my PIN (as i don't use face ID.)

is that really more secure than a password, considering a password is typically
much stronger than a device PIN, which is usually 4-6 digits?

from Microsoft regarding Windows Hello, their passkey solution:

> The use of a PIN doesn't compromise security, since 
> Windows Hello has built-in brute force protection, 
> and the PIN never leaves the device[^msft]

devices that use PIN or biometric authentication often will have
a timeout implemented in hardware.

law enforcement can compel you to unlock with a biometric, but
not with a PIN or passcode.

[^lapcat]: https://lapcatsoftware.com/articles/2023/5/1.html
[^goog]: https://www.youtube.com/watch?v=2xdV-xut7EQ
[^palant]: https://palant.info/2023/09/05/a-year-after-the-disastrous-breach-lastpass-has-not-improved/
[^msft]: https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/

## more tutorials
[webauthn/fido2 codelab](https://glitch.com/edit/#!/webauthn-codelab-start)
[awesome-webauthn](https://github.com/herrjemand/awesome-webauthn)
[awesome-fido2](https://github.com/deepzz0/awesome-fido2)
