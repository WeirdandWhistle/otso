import * as db from "./databaseInteraction.js";
import { getUserIfSession } from "./sessions.js";
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateAccessToken, generateRefreshToken } from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';

// OAuth 2.0 endpoints
export async function authorize(request, env, KV){
    if(request.method != "GET")
        return new Response("400 Bad request. The appropriate HTTP method is 'GET'.", {status: 400});
    // console.log(request.url);
    const query = new URL(request.url).searchParams;

    const client_id = query.get("client_id");
    const response_type = query.get("response_type");
    if(!client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!response_type){
        return new Response(`{"error":"invalid_request","error_description":"response_type must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }

    const OAuthClient = await db.getOAuthClientFromClientID(env, client_id);
    if(!OAuthClient)
        return new Response(`{"error":"invalid_request","error_description":"404 Client does not exist. Check your client_id field."}`, {status: 404});

    let redirect_uri = query.get("redirect_uri");
    let verifiyedRedirectURI = false;
    const redirectionURIs = OAuthClient.redirection_URIs ? OAuthClient.redirection_URIs.split(" ") : null;
    console.log("redirectionURIs",redirectionURIs);
    if(redirectionURIs || redirect_uri){
        if(!redirectionURIs && redirect_uri){
            verifiyedRedirectURI = true;
        } else if(redirectionURIs.length == 1){
            if(redirect_uri && redirect_uri != redirectionURIs[0])
                return new Response(`{"error":"invalid_request","error_description":"redirect_uri is incorrect. Must have one valid redirect_uri. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
            verifiyedRedirectURI = true;
            redirect_uri = redirectionURIs[0];
        } else if(!verifiyedRedirectURI && redirectionURIs.length > 1){
            for(const uri of redirectionURIs){
                if(uri == redirect_uri){
                    verifiyedRedirectURI = true;
                    break;
                }
            }
        return new Response(`{"error":"invalid_request","error_description":"redirect_uri does not equal any registered URI."}`,{status:400});
        }
    } else {
        return new Response(`{"error":"invalid_request","error_description":"A redirection must be registered OR provided."}`,{status:400});
    }
    if(!verifiyedRedirectURI)
        return new Response(`{"error":"server_error","error_description":"Sorry, the server ran into an unexpected edge case. Please contact an admin"}`,{status:500});
    if(!query.get("scope"))
        return new Response(`{"error":"invalid_scope","error_description":"Scope can not be nothing."}`,{status:400});

    try {
        const testForErrorURL = new URL(redirect_uri);
    } catch (error) {
        return new Response(`{"error":"invalid_request","error_description":"redirect_uri is not a valid URL."}`,{status:400});
    }

    const scopes = query.get("scope").split(" ");
		if(query.get("scope").includes(";"))
			return new Response(`{"error":"invalid_scope","error_description":"Scope can not contain ';'."}`,{status:400});
    if(scopes.length == 0)
        return new Response(`{"error":"invalid_scope","error_description":"Scope can not be nothing."}`,{status:400});

    let user = await getUserIfSession(request, env);
    if(!user){
        // TODO: send to login/signup/authenticaton page
		    const state = generateSecureChars(32);
				const stateJson = {
					redirect_from: request.url,
				};
			  KV.put(`state.${state}`, stateJson, 60);


			return new Response("You are currently being redirected to /login.", {
				status: 302,
				headers:{
					'Location':`/login?state=${state}`
				}
			});
    }

    const authorizedApps = user.authorizedApps;
    let isAppAuthorized = false;
    if(authorizedApps){
			const apps = parseScopes(authorizedApps);
			if(apps.has(OAuthClient.client_id)){
				isAppAuthorized = true;
				for(const scope of scopes){
					if(!apps.get(OAuthClient.client_id).has(scope)){
						isAppAuthorized = false;
						break;
					}
				}
			}
    }
    if(!isAppAuthorized){
        const HTMLPage = await env.ASSETS.fetch(new Request(`${new URL(request.url).origin}/authorizeApp.html`)); // forges a request to get the HTML page from assets
        const dataToEncode = { // data to be passed to frontend
            appName: OAuthClient.name,
            username: user.username,
            redirect_uri: redirect_uri,
        };
        let base64Encoded;
        if(1){ // name space shenaigins
            // encodes dataToEncode into base64 becuase its being passed as a cookie
            const arr = new TextEncoder().encode(JSON.stringify(dataToEncode));
            base64Encoded = arr.toBase64({alphabet: "base64url", omitPadding: true});
        }

        const headers = new Headers(HTMLPage.headers); // steals header from the static assets response
        headers.append("Set-Cookie", `authorizeAppData=${base64Encoded}; Expires=${new Date(Date.now() + 5 * 1000).toUTCString()}; Path=/`); // set a cookie of the base64 encoded data that lasts 5 seconds

        const body = await HTMLPage.text(); // get the html page
        // bundle everything and send to frontend
        const res = new Response(body, {
            headers: headers,
            status: 200,
        });
        return res;
    }


	if(response_type == "code"){
			const code = generateSecureChars(42);

			KV.put(`OAuthCode.${code}`, {client: OAuthClient, user: user, redirect_uri: redirect_uri, scopes: scopes});

			const redirectTo = new URL(redirect_uri);
			redirectTo.searchParams.set("code", code);
			redirectTo.searchParams.set("state", query.get("state"));

			const goingTo = redirectTo.toString();
			return new Response(`You are currently being redirected to ${goingTo}.`,{
				status: 302,
				headers: {
					'Location' : goingTo
				}
			});
    } else if(response_type == "token"){
			const tokens = await issueAccessToken(env, user.userID, OAuthClient.client_id, scopes, 3600, false);

			const goingToParam = new URLSearchParams();
			goingToParam.set("access_token", tokens.access_token);
			goingToParam.set("token_type", 'access_token');
			goingToParam.set("state", query.get("state"));
			goingToParam.set("expires_in", 3600);
			goingToParam.set("scope", query.get("scope"));

			const goingTo = `${redirect_uri}#${goingToParam.toString()}`;
			return new Response(`You are being redirected to <a href="${goingTo}">${goingTo}</a>`,{
				status: 302,
				headers:{
					'Location' : goingTo
				}
			});
    } else {
			return new Response("Sorry, that response_type is not currently supported. Try either 'code' or 'token'.", {status: 404});
    }
}
export async function token(request, env, KV){
    if(request.method != "POST")
        return new Response("400 Bad request. The appropriate HTTP method is 'POST'.", {status: 400});
    const query = new URLSearchParams(await request.text());

    const code = query.get("code");
    const stateJson = KV.get(`OAuthCode.${code}`);
    const redirect_uri = query.get("redirect_uri");
    const grant_type = query.get("grant_type");
    if(!code){
        return new Response(`{"error":"invalid_request","error_description":"code must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!stateJson){
        return new Response(`{"error":"invalid_request","error_description":"code has been used, expired, or never existed."}`, {status: 400});
    } if(redirect_uri != stateJson.redirect_uri){
        return new Response(`{"error":"invalid_request","error_description":"redirect_uri must equal the one used to get the 'code'. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(grant_type != "authorization_code"){
        return new Response(`{"error":"invalid_request","error_description":"grant_type must be 'authorization_code'. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }
    KV.remove(`OAuthCode.${code}`);

    let client_id;
    let client_secret;

    if(request.header.get("Authorization")){
        const authArray = request.header.get("Authorization").split(" ");
        const tokenType = authArray[0];
        if(tokenType.toLowerCase != 'basic')
            return new Response(`{"error":"invalid_client","error_description":"When using HTTP Authorization you MUST use the 'Basic' token type. (eg, 'Basic 123xyz')) as defined Here: https://datatracker.ietf.org/doc/html/rfc2617#section-2"}`,{status: 401});
        const decodedBase64Array = window.atob(authArray[1]).split(":");
        client_id = decodedBase64Array[0];
        client_secret = decodedBase64Array[1];
    } else {
        client_id = query.get("client_id");
        client_secret = query.get("client_secret");
    }

    const response_type = query.get("response_type");
    if(!client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!client_secret){
        return new Response(`{"error":"invalid_client","error_description":"client_secret must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(client_id != stateJson.client.client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id used to gain 'code' must be the same as the one exchangeing for an access_token."}`, {status: 400});
    } if(!crypto.timingSafeEqual(client_secret, stateJson.client.client_secret)){
        return new Response(`{"error":"invalid_client","error_description":"client_secret is incorrect"}`, {status: 401});
    } if(!response_type){
        return new Response(`{"error":"invalid_request","error_description":"response_type must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }

    const tokens = await issueAccessToken(env, stateJson.user.userID, client_id, stateJson.scopes, 3600, true);
    return new Response(JSON.stringify(tokens));
}
async function issueAccessToken(env, userID, client_id, scopes, ttl, issuerefresh_token=true){
	const access_token = generateAccessToken();
	const refresh_token = issuerefresh_token ? generateRefreshToken() : null;
	const expires = (Date.now()/1000) + ttl;
	let scope = "";
	scopes.forEach((e)=> scope += e + " ")

	await db.createOAuthToken(env, access_token, expires, scope, refresh_token, userID, client_id);

	return {
		access_token: access_token,
		token_type: "Bearer",
		expires_in: ttl,
		refresh_token: refresh_token,
	};
}
