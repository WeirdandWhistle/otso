import * as db from "./databaseInteraction.js";
import * as session from "./sessions.js";
import * as jwt from "./JWT.js";
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateAccessToken, generateRefreshToken, safeCompareString } from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';

// OAuth 2.0 endpoints
export async function authorize(request, env, KV, OIDC_KEY_PAIR){
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
		if(OAuthClient.client_type == 'public' &&  response_type == 'code')
        return new Response(`{"error":"invalid_request","error_description":"400 A public client can not request a code. It must user the implict/token protocol."}`, {status: 400});
		if(OAuthClient.client_type == 'confidential' &&  response_type == 'token')
        return new Response(`{"error":"invalid_request","error_description":"400 A confidential client can not request a token. It must use code protocol."}`, {status: 400});

    let redirect_uri = query.get("redirect_uri");
    let verifiyedRedirectURI = false;
    const redirectionURIs = OAuthClient.redirection_URIs ? OAuthClient.redirection_URIs.split(" ") : null;
    // console.log("redirectionURIs",redirectionURIs);
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

    let user = await session.getUserIfSession(request, env);
    // console.log("oauth user",user);
    if(!user){
        // TODO: send to login/signup/authenticaton page
		    const state = generateSecureChars(32);
				const stateJson = {
					redirect_from: request.url,
				};
			  await KV.put(`state.${state}`, stateJson, 60);


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

			await KV.put(`OAuthCode.${code}`, {
                client: OAuthClient,
                user: user,
                redirect_uri: redirect_uri,
                scopes: scopes,
                pkce:{
                    nonce: query.get("nonce"),
                }
            });

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
					'Location' : goingTo,
				}
			});
    } else if(response_type == "id_token"){
        // console.log("key pair", OIDC_KEY_PAIR);
        const header = jwt.JOSEHeader;
        header.kid = OIDC_KEY_PAIR.kid;
        const claims = {};
        if(!scopes.includes("openid"))
            return new Response("400 Bad Request. Must have scope 'openid' to use id_token.",{status:400});
        if(scopes.includes("profile")){
            claims.name = user.username;
            claims.preferred_username = user.username;
        }
        if(scopes.includes("email")) claims.email = user.email;
        // console.log("claims",claims);
        const payload = jwt.generatePayload(new URL(request.url).origin, user.userID, client_id, (Date.now()/1000)+3600, (Date.now()/1000), query.get("nonce"), claims);
        const signature = await jwt.generateSignaute(header, payload, OIDC_KEY_PAIR.keypair.privateKey);
        const id_token = jwt.encodeFullJWT(header, payload, signature);
        
        const q = new URLSearchParams();
        q.set("expires_in", 3600);
        q.set("id_token", id_token);
        q.set("state", query.get("state"));
        const goingTo = `${redirect_uri}#${q.toString()}`;
        // console.log("id_token", id_token);
        return new Response(`You're are currently being redirected to <a href="${goingTo}">${goingTo}</a>`,{
            status: 302,
            headers:{
                'Location' : goingTo
            },
        });
    } else {
		return new Response("Sorry, that response_type is not currently supported. Try 'code', 'token', or 'id_token'.", {status: 404});
    }
}
export async function token(request, env, KV, OIDC_KEY_PAIR){
    if(request.method != "POST")
        return new Response("405 Method Not Allowed. The appropriate HTTP method is 'POST'.", {status: 405});
    const query = new URLSearchParams(await request.text());

    const code = query.get("code");
    const stateJson = await KV.get(`OAuthCode.${code}`);
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
    await KV.remove(`OAuthCode.${code}`);

    let client_id;
    let client_secret;

    if(request.headers.get("Authorization")){
        const authArray = request.header.get("Authorization").split(" ");
        const tokenType = authArray[0];
        if(tokenType.toLowerCase() != 'basic')
            return new Response(`{"error":"invalid_client","error_description":"When using HTTP Authorization you MUST use the 'Basic' token type. (eg, 'Basic 123xyz')) as defined Here: https://datatracker.ietf.org/doc/html/rfc2617#section-2"}`,{status: 401});
        const decodedBase64Array = window.atob(authArray[1]).split(":");
        client_id = decodedBase64Array[0];
        client_secret = decodedBase64Array[1];
		} else {
        client_id = query.get("client_id");
        client_secret = query.get("client_secret");
    }
	const client_secret_hash = await base64SHA256(client_secret);

    const response_type = query.get("response_type");
    if(!client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!client_secret){
        return new Response(`{"error":"invalid_client","error_description":"client_secret must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(client_id != stateJson.client.client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id used to gain 'code' must be the same as the one exchangeing for an access_token."}`, {status: 400});
    } if(!safeCompareString(client_secret_hash, stateJson.client.client_secret_hash)){
        return new Response(`{"error":"invalid_client","error_description":"client_secret is incorrect"}`, {status: 401});
    }

    const tokens = await issueAccessToken(env, stateJson.user.userID, client_id, stateJson.scopes, 3600, true);
    if(stateJson.scopes.includes("openid")){
        const scopes = stateJson.scopes;
        const user = stateJson.user;

        const header = jwt.JOSEHeader;
        header.kid = OIDC_KEY_PAIR.kid;
        const claims = {};
        if(!scopes.includes("openid"))
            return new Response("400 Bad Request. Must have scope 'openid' to use id_token.",{status:400});
        if(scopes.includes("profile")){
            claims.name = user.username;
            claims.preferred_username = user.username;
        }
        if(scopes.includes("email")) claims.email = user.email;
        const payload = jwt.generatePayload(new URL(request.url).origin, user.userID, client_id, (Date.now()/1000)+3600, (Date.now()/1000), stateJson.pkce.nonce, claims);
        const signature = await jwt.generateSignaute(header, payload, OIDC_KEY_PAIR.keypair.privateKey);
        const id_token = jwt.encodeFullJWT(header, payload, signature);
        tokens.id_token = id_token;
    }
    return new Response(JSON.stringify(tokens), {
			headers:{
				'Access-Control-Allow-Origin':'*',
                'Content-Type':'application/json'
			}
		});
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
export async function tempToken(request, env, KV) {
    if(await session.useCSRFToken(request, env, KV) != true)
            return new Response("401 Unauthorized. Wrong CSRFToken.",{status:401});
    if(request.method != 'GET')
        return new Response("405 Method Not Allowed. Try using 'GET'", {status:405});
    const user = await session.getUserIfSession(request, env);
    if(!user)
        return new Response("401 Unauthorized. That session does not exist or is invalid.", {status: 401});
    const client_id = new URL(request.url).searchParams.get("client_id");
    const client = await db.getOAuthClientFromClientID(env, client_id);
    if(!client)
        return new Response("404 Not Found. That client does not exist.", {status: 404});
    if(client.ownerUserID != user.userID)
        return new Response("401 Unauthorized. User/Sessions does not own that client.",{status:401});

    const tokens = await issueAccessToken(env, user.userID, client_id, allScopes, 3600, true);
    return new Response(JSON.stringify(tokens));
}
const allScopes = ["username","id","email"];
