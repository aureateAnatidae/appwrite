<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://openid.net/connect/faq/

class Oidc extends OAuth2
{
    /**
     * @var array
     */
    protected array $scopes = ["openid", "profile", "email"];

    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @var string
     */
    private string $pkce = "";

    /**
     * @return string
     */
    private function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), "+/", "-_"), "=");
    }

    /**
     * @return string
     */
    private function getPKCE(): string
    {
        $fakelog = fopen("aintlog.txt", "w");
        fwrite($fakelog, "This is the PKCE as getPKCE() is called: ");
        fwrite($fakelog, $this->pkce);
        fwrite($fakelog, "\n");
        if (empty($this->pkce)) {
            // "Good" is used to refer to a condition in which the Zitadel PKCE
            // OIDC authenticator successfully returns the token in $this->getTokens.
            //
            // "No good" refers to the WARN log returned by Zitadel written:
            // msg="request error" oidc_error.description="invalid code challenge" oidc_error.type=invalid_grant status_code=400
            //
            // handled by appwrite's error handler as:
            //
            // [Error] Timestamp: 2025-05-14T16:43:09+00:00
            // [Error] Method: GET
            // [Error] URL: /v1/account/sessions/oauth2/:provider/redirect
            // [Error] Type: Appwrite\Extend\Exception
            // [Error] Message: Failed to obtain access token. The OpenID Connect OAuth2 provider returned an error: invalid_grant: invalid code challenge
            // [Error] File: /usr/src/code/app/controllers/api/account.php
            // [Error] Line: 1298
            //
            // Which I surmise equates to "base64url(code_verifier) != code_challenge".
            //
            // Note as well that the occurrences of each case do not appear (to my human eyes)
            // to differ within themselves (same case, same error message).
            //
            // Below are the attempts annotated with the keywords referring to their
            // respective cases as defined above:

            // No good - but this is what we want to be good.
            $this->pkce = $this->base64url(random_bytes(rand(43, 128)));

            // No good
            $this->pkce = $this->base64url((rand(43, 128)));

            // No good
            $this->pkce = $this->base64url(random_bytes(60));

            // No good
            $this->pkce = rand(43, 128);

            // Good
            $this->pkce = $this->base64url(60);



            // No good - see Etsy.php in this directory
            $this->pkce = bin2hex(random_bytes(rand(43, 128)));

            // No good
            $this->pkce = bin2hex(random_bytes(60));

            // Good - strings are bytes
            $this->pkce = bin2hex("
                Good is used to refer to a condition in which the Zitadel PKCE
                OIDC authenticator successfully returns the token in this->getTokens.

                No good refers to the WARN log returned by Zitadel written:
                msg=request error oidc_error.description=invalid code challenge oidc_error.type=invalid_grant status_code=400

                handled by appwrite's error handler as:

                [Error] Timestamp: 2025-05-14T16:43:09+00:00
                [Error] Method: GET
                [Error] URL: /v1/account/sessions/oauth2/:provider/redirect
                [Error] Type: Appwrite\Extend\Exception
                [Error] Message: Failed to obtain access token. The OpenID Connect OAuth2 provider returned an error: invalid_grant: invalid code challenge
                [Error] File: /usr/src/code/app/controllers/api/account.php
                [Error] Line: 1298

                Which I surmise equates to base64url(code_verifier) != code_challenge.
                Note as well that the occurrences of each case do not appear (to my human eyes)
                to differ within themselves (same case, same error message).

                Below are the attempts annotated with the keywords referring to their
                respective cases as defined above:
            ");

            // Good! - Running base64url(random_bytes(rand(43, 128))) on my laptop.
            $this->pkce = "lXDpg--eueH0nQsiuiVOj6FG9LaIjp6XJifQalFfEU5BQaN-SAZD1ivSqPBJQqVxpjgD-akGyShdyDycpbL6a8VIiApaDqSibqr9dcqjgQkv2nmiv5qJUw6LXWM0Moo3IQQULljmtZ6eiLvipjnMLY76n-WphoNpcvMb_b6lriQ";

            // Good
            $this->pkce = "60";

            $this->pkce = $this->base64url(random_bytes(rand(43, 128)));
            // I am tempted to conclude that something is strange with random generation.

            fwrite($fakelog, "This is the randomly generated base64url PKCE: ");
            fwrite($fakelog, $this->pkce);
            fwrite($fakelog, "\n");
            fwrite($fakelog, "This is the base64url hash of the previous PKCE: ");
            fwrite($fakelog, $this->base64url(hash('sha256', $this->pkce, true)));
            fwrite($fakelog, "\n");
            // The output in aintlog.txt is:
            // iu-0BPFDOjpFo6-DJfbSf69vIa9lL8r_CFBXGR0HtLuKp1MB_WG0o1g3ApRYxPnQ7oCaOnkFL_v-JhcZWSnceg
            // Xv0KFHWNeOviBnyqVQ3QmCJq_ZroQh_6Xs393la25fY
            //
            // But this is entirely correct!

            // Now I suspect the if (empty($this->pkce) clause
            // If each run is empty($this->pkce), this completely explains why any introduction
            // of randomness breaks this function!
            // We don't need to write any more code to test this.
            // Repeat this function over and over. Constantly call it.
            // If empty($this->pkce) is true, or $this->pkce is constantly being reset
            // then multiple lines will be written in aintlog.txt.
            //
            // And it does! New PKCEs are written in aintlog.txt every time a request is made.
            // However, the program shouldn't even be saving the random string across requests. A request to
            // an OAuth provider under PKCE probably doesn't want to reuse these codes across requests.
            // A new random string should be generated for each request.
            //
            // How should the random string be locked to that request?
        }
        return $this->pkce;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return "oidc";
    }

    protected array $wellKnownConfiguration = [];

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return $this->getAuthorizationEndpoint() .
            "?" .
            \http_build_query([
                "client_id" => $this->appID,
                "redirect_uri" => $this->callback,
                "state" => \json_encode($this->state),
                "scope" => \implode(" ", $this->getScopes()),
                "response_type" => "code",
                "prompt" => "select_account",
                // Observe as well that hash(algo, $str) requires that the third argument requires "true".
                // Otherwise, I receive a "No good" case.
                // I haven't checked if this breaks Etsy.
                "code_challenge" => $this->base64url(hash('sha256', $this->getPKCE(), true)),
                "code_challenge_method" => "S256",
            ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $headers = ["Content-Type: application/x-www-form-urlencoded"];
            $this->tokens = \json_decode(
                $this->request(
                    "POST",
                    $this->getTokenEndpoint(),
                    $headers,
                    \http_build_query([
                        "code" => $code,
                        "client_id" => $this->appID,
                        "client_secret" => $this->getClientSecret(),
                        "redirect_uri" => $this->callback,
                        "grant_type" => "authorization_code",
                        "code_verifier" => $this->getPKCE(),
                    ])
                ),
                true
            );
        }
        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $headers = ["Content-Type: application/x-www-form-urlencoded"];
        $this->tokens = \json_decode(
            $this->request(
                "POST",
                $this->getTokenEndpoint(),
                $headers,
                \http_build_query([
                    "refresh_token" => $refreshToken,
                    "client_id" => $this->appID,
                    "client_secret" => $this->getClientSecret(),
                    "grant_type" => "refresh_token",
                ])
            ),
            true
        );

        if (empty($this->tokens["refresh_token"])) {
            $this->tokens["refresh_token"] = $refreshToken;
        }

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        if (isset($user["sub"])) {
            return $user["sub"];
        }

        return "";
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        if (isset($user["email"])) {
            return $user["email"];
        }

        return "";
    }

    /**
     * Check if the User email is verified
     *
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);

        return $user["email_verified"] ?? false;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        if (isset($user["name"])) {
            return $user["name"];
        }

        return "";
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $headers = ["Authorization: Bearer " . \urlencode($accessToken)];
            $user = $this->request(
                "GET",
                $this->getUserinfoEndpoint(),
                $headers
            );
            $this->user = \json_decode($user, true);
        }

        return $this->user;
    }

    /**
     * Extracts the Client Secret from the JSON stored in appSecret
     *
     * @return string
     */
    protected function getClientSecret(): string
    {
        $secret = $this->getAppSecret();

        return $secret["clientSecret"] ?? "";
    }

    /**
     * Extracts the well known endpoint from the JSON stored in appSecret.
     *
     * @return string
     */
    protected function getWellKnownEndpoint(): string
    {
        $secret = $this->getAppSecret();
        return $secret["wellKnownEndpoint"] ?? "";
    }

    /**
     * Extracts the authorization endpoint from the JSON stored in appSecret.
     *
     * If one is not provided, it will be retrieved from the well-known configuration.
     *
     * @return string
     */
    protected function getAuthorizationEndpoint(): string
    {
        $secret = $this->getAppSecret();

        $endpoint = $secret["authorizationEndpoint"] ?? "";
        if (!empty($endpoint)) {
            return $endpoint;
        }

        $wellKnownConfiguration = $this->getWellKnownConfiguration();
        return $wellKnownConfiguration["authorization_endpoint"] ?? "";
    }

    /**
     * Extracts the token endpoint from the JSON stored in appSecret.
     *
     * If one is not provided, it will be retrieved from the well-known configuration.
     *
     * @return string
     */
    protected function getTokenEndpoint(): string
    {
        $secret = $this->getAppSecret();

        $endpoint = $secret["tokenEndpoint"] ?? "";
        if (!empty($endpoint)) {
            return $endpoint;
        }

        $wellKnownConfiguration = $this->getWellKnownConfiguration();
        return $wellKnownConfiguration["token_endpoint"] ?? "";
    }

    /**
     * Extracts the userinfo endpoint from the JSON stored in appSecret.
     *
     * If one is not provided, it will be retrieved from the well-known configuration.
     *
     * @return string
     */
    protected function getUserinfoEndpoint(): string
    {
        $secret = $this->getAppSecret();
        $endpoint = $secret["userinfoEndpoint"] ?? "";
        if (!empty($endpoint)) {
            return $endpoint;
        }

        $wellKnownConfiguration = $this->getWellKnownConfiguration();
        return $wellKnownConfiguration["userinfo_endpoint"] ?? "";
    }

    /**
     * Get the well-known configuration using the well known endpoint
     */
    protected function getWellKnownConfiguration(): array
    {
        if (empty($this->wellKnownConfiguration)) {
            $response = $this->request("GET", $this->getWellKnownEndpoint());
            $this->wellKnownConfiguration = \json_decode($response, true);
        }

        return $this->wellKnownConfiguration;
    }

    /**
     * Decode the JSON stored in appSecret
     *
     * @return array
     */
    protected function getAppSecret(): array
    {
        try {
            $secret = \json_decode(
                $this->appSecret,
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (\Throwable $th) {
            throw new \Exception("Invalid secret");
        }
        return $secret;
    }
}
