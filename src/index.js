/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
* - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

const userAgent = "Otso-Guardian/1.0 (compatible; Otsobot/1.0; +https://otso.whynotjava.net)";
// OAuth providers to add: gitlab, facebook, bitbucket, yahoo, spotify. all of these might not be free so we'll see...
import { getGithubUserEmail, getGithubUser, getGoogleUser, getSlackUser, getDiscordUser, getTwitchUser } from "./getUserData.js";
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';
import * as db from "./databaseInteraction.js";
import * as KV from "./customKV.js";
import * as session from "./sessions.js";
import * as OAuthProvider from "./OAuthProviderAPI.js";
import * as OAuthClients from './OAuthClients.js';

export default {
	async fetch(request, env, ctx) {
		const pathname = new URL(request.url).pathname;

		const redirect_uri = "http://localhost:8787/callback";

		if(pathname.startsWith("/oauth/")){
			let forward_url;
			const query = new URLSearchParams();
			const response_type = "code"; query.set("response_type", response_type);
			query.set("redirect_uri", redirect_uri);
			const urlQuery = new URL(request.url).searchParams;
			let state = urlQuery.get("state");
			const redirect_from = urlQuery.get("redirect_from");
			if(!state)
				state = generateRandomString(32);
			query.set("state", state);
			let client_id;
			let provider;

			if(pathname.endsWith("/github")){
				forward_url = new URL("https://github.com/login/oauth/authorize");
				client_id = env.GITHUB_CLIENT_ID;
				provider = "github";
			} else if(pathname.endsWith("/google")){
				forward_url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
				client_id = env.GOOGLE_CLIENT_ID;
				query.set("scope", "email profile");
				provider = "google";
			} else if(pathname.endsWith("/slack")){
				forward_url = new URL("https://slack.com/oauth/v2/authorize");
				client_id = env.SLACK_CLIENT_ID;
				query.set("scope", "users:read");
				provider = "slack";
			} else if(pathname.endsWith("/discord")){
				forward_url = new URL("https://discord.com/oauth2/authorize");
				client_id = env.DISCORD_CLIENT_ID;
				query.set("scope", "identify email");
				provider = "discord";
			} else if(pathname.endsWith("/twitch")){
				forward_url = new URL("https://id.twitch.tv/oauth2/authorize");
				client_id = env.TWITCH_CLIENT_ID;
				query.set("scope", "user:read:email");
				provider = "twitch";
			} else {
				throw new Error("That OAuth 2.0 provider is currently not supported");
			}

			let stateJson = KV.get(`state.${state}`);
			if(!stateJson)
				stateJson = {};
			if(redirect_from && !stateJson.redirect_from)
				stateJson.redirect_from = redirect_from;
			console.log("oauth/state", stateJson);
			stateJson.auth = provider;
			KV.put(`state.${state}`, stateJson, 60);
			query.set("client_id", client_id);

			forward_url.search = query.toString();
			return new Response("You are currently being redirected to " + forward_url.toString(),{
				status: 302,
				headers: {
					'Location' : forward_url.toString()
				},
			});
		} else if(pathname == "/callback"){
			const githubTokenEndpoint = "https://github.com/login/oauth/access_token";
			const googleTokenEndpoint = "https://oauth2.googleapis.com/token";
			const slackTokenEndpoint = "https://slack.com/api/oauth.v2.access";
			const discordTokenEndpoint = "https://discord.com/api/oauth2/token";
			const twitchTokenEndpoint = "https://id.twitch.tv/oauth2/token";
			const query = new URL(request.url).searchParams;
			const code = query.get("code");
			const state = query.get("state");
			const grant_type = "authorization_code";

			if(!code || !state)
				return new Response("No client should ever be here without the quary params 'code' and 'state' for OAuth 2.0.", { status: 400 });

			// const KVstateTemp = await env.OAUTH_STATE.get(state);
			let OAuthState = KV.get(`state.${state}`);
			if(!OAuthState)
				return new Response("Invalid State", {status: 400});

			const body = new URLSearchParams();
			body.set("grant_type", grant_type);
			body.set("code", code);
			body.set("redirect_uri", redirect_uri);

			let endpoint;

			if(OAuthState.auth == "github"){
				body.set("client_id", env.GITHUB_CLIENT_ID);
				body.set("client_secret", env.GITHUB_CLIENT_SECRET);
				endpoint = githubTokenEndpoint;
			} else if(OAuthState.auth == "google"){
				body.set("client_id", env.GOOGLE_CLIENT_ID);
				body.set("client_secret", env.GOOGLE_CLIENT_SECRET);
				endpoint = googleTokenEndpoint;
			} else if(OAuthState.auth == "slack"){
				body.set("client_id", env.SLACK_CLIENT_ID);
				body.set("client_secret", env.SLACK_CLIENT_SECRET);
				endpoint = slackTokenEndpoint;
			} else if(OAuthState.auth == "discord"){
				body.set("client_id", env.DISCORD_CLIENT_ID);
				body.set("client_secret", env.DISCORD_CLIENT_SECRET);
				endpoint = discordTokenEndpoint;
			} else if(OAuthState.auth == "twitch"){
				body.set("client_id", env.TWITCH_CLIENT_ID);
				body.set("client_secret", env.TWITCH_CLIENT_SECRET);
				endpoint = twitchTokenEndpoint;
			}

			const res = await fetch(endpoint, {
				method: 'POST',
				headers: {
					'Content-Type' : 'application/x-www-form-urlencoded',
				},
				body: body.toString(),
			});

			const resText = await res.text();

			if(!res.ok){
				return new Response("Sorry, the authorization code exchanged failed :( Text: " + resText);
			}

			let tokens = {};

			switch(res.headers.get("content-type").split(";")[0]){
				case "application/x-www-form-urlencoded":
					const s = new URLSearchParams(resText);
					s.forEach((value, key) => tokens[key] = value);
					break;
				case "application/json":
					tokens = JSON.parse(resText);
					break;
				default:
					return new Response("Could not detect a usable format for token exchange");
			}

			let issuerInfo; // {username, id, email, issuer}

			if(OAuthState.auth == "github"){
				issuerInfo = await getGithubUser(tokens.access_token);
				issuerInfo.email = await getGithubUserEmail(tokens.access_token);
			} else if(OAuthState.auth == "google"){
				issuerInfo = await getGoogleUser(tokens.access_token);
			} else if(OAuthState.auth == "slack"){
				issuerInfo = await getSlackUser(tokens);
			} else if(OAuthState.auth == "discord"){
				issuerInfo = await getDiscordUser(tokens.access_token);
			} else if(OAuthState.auth == "twitch"){
				issuerInfo = await getTwitchUser(tokens.access_token, env.TWITCH_CLIENT_ID);
			} else {
				throw new Error("Huh..?");
			}
			issuerInfo.access_token = tokens.access_token;
			issuerInfo.refresh_token = tokens.refresh_token;

			const user = await db.getUserFromIssuer(env, issuerInfo.id, issuerInfo.issuer);
			console.log("after authed: user from db, ", user);
			if(!user){

				OAuthState.issuerInfo = issuerInfo;
				KV.put(`state.${state}`, OAuthState, 60);

				const sp = new URLSearchParams();
				sp.set("state", state);
				sp.set("username", issuerInfo.username);
				sp.set("email", issuerInfo.email);

				const toURL = "/firstTime?" + sp.toString();

				return new Response("You are currently being redirected to "+toURL,{
					status: 302,
					headers: {
						"Location" : toURL
					}
				});
			} else {
				const sessionID = await session.issueSession(env, user.userID, request.headers);
				const sessionCookie = session.getCookie(sessionID);
				if(OAuthState.redirect_from){
					return new Response("You are currently being redirected to: "+OAuthState.redirect_from,{
						status: 302,
						headers:{
							"Location": OAuthState.redirect_from,
							"Set-Cookie": sessionCookie
						}
					});
				} else {
					KV.remove(state);
					return new Response(JSON.stringify(issuerInfo),{
						headers:{
							'Content-Type' : 'application/json'
						}
					});
				}
			}
			throw new Error("this code is unreachable");
		}

		if(pathname.startsWith("/api/")){
			if(ratelimit(KV, `${request.headers.get("CF-Connecting-IP")}`, 60))
				return new Response("429 Too Many Requets", {status: 429});
			if(pathname.startsWith("/api/account/createAccount")){
				if(request.method != 'POST')
					return new Response("405 Method Not Allowed", {status:405});
				const postJson = await request.json();
				const state = postJson.state;

				const OAuthState = KV.get(`state.${state}`);
				if(!OAuthState)
					return new Response(`{"ok":false,"error":"invalid_state"}`, { status: 400 });
				// console.log("OAuthState createACoount", OAuthState);
				// console.log("postJson createACoount", postJson);

				let username = OAuthState.issuerInfo.username;
				if(validUsername(postJson.username))
					username = postJson.username;
				if(!validUsername(username))
					username = correctUsername(username);

				let email = OAuthState.issuerInfo.email;
				const id = OAuthState.issuerInfo.id;
				const issuer = OAuthState.issuerInfo.issuer;
				const access_token = OAuthState.issuerInfo.access_token;
				const refresh_token = OAuthState.issuerInfo.refresh_token;

				const userID = generateUserID();
				await db.createUser(env, userID, username, email, issuer, id, OAuthState.issuerInfo.username, email, access_token, refresh_token);

				const headers = new Headers();

				const sessionID = await session.issueSession(env, userID, request.headers);
				const sessionCookie = session.getCookie(sessionID);
				headers.append("Set-Cookie", sessionCookie);
				headers.append("Content-Type","application/json");
				//console.log('oauthstae',OAuthState);

				return new Response(JSON.stringify({
						ok: true,
						redirect_uri: OAuthState.redirect_from,
					}), {
					status: 200,
					headers: headers,
				});
			} else if(pathname.startsWith("/api/account/info")){
				if(request.method != 'GET')
					return new Response("405 Method Not Allowed. Try using the 'GET' method.",{status: 405});
				const authHeader = request.headers.get("Authorization");
				const authType = authHeader.split(" ")[0].toLowerCase();
				if(authType == "session"){
					const user = await session.getUserIfSession(request, env);
					//console.log("user",user);
					if(!user)
						return new Response(`401 Unauthorized. Session is invalid.`, {status: 401});
					const out = {};
					out.username = user.username;
					out.userID = user.userID;
					out.email = user.email;
					out.loginMethods = user.authenticationMethods.split(" ");
					out.authorizedApps = [];

					const clientIDArray = user.authorizedApps.split(" ");
					for(let client_id of clientIDArray){
						const client = await db.getOAuthClientFromClientID(env, client_id);
						if(!client){
							//console.log("client_id",client_id,"is null");
							continue;
						}
						out.authorizedApps.push({
							name: client.name,
							client_id: client.client_id,
						});
					}
					out.ownedClients = [];
					const ownedClients = await db.getOAuthClientsFromUserID(env, user.userID);
					//console.log(ownedClients);
					if(ownedClients){
						for(const client of ownedClients){
							out.ownedClients.push({
								name: client.name,
								client_id: client.client_id,
								redirect_uri: client.redirection_URIs.split(" "),
								client_type: client.client_type,
							});
						}
					}
					return new Response(JSON.stringify(out));
				} else if(authType == "bearer"){
					return new Response("501 Not Implemented. Meant for access_tokens, but that doesnt exist right now.", {status: 502});
				} else {
					return new Response("401 Unauthorized. Unknown auth-scheme. Try 'Bearer' or 'Session'.", {status: 401});
				}
			} else if(pathname.startsWith("/api/account/authorizeApp")){
				if(request.method != 'POST')
					return new Response("405 Method Not Allowed. Try using 'POST'", {status:405});

				const user = await session.getUserIfSession(request, env);
				if(!user)
					return new Response("401 Unauthorized. That session does not exist or is invalid.", {status: 401});

				const requestJson = await request.json();
				if(!requestJson.client_id)
					return new Response("400 Bad Request. This enpoint requires a 'client_id' in the JSON.", {status: 400});

				const client = await db.getOAuthClientFromClientID(env, requestJson.client_id);

				if(!client)
					return new Response("400 Bad Request. Client does not exist.",{status: 400});

				await db.addAuthorizedApp(env, user.userID, client.client_id);
				return new Response(`{"ok":true,"message":"App has been Authorized."}`);
			} else if(pathname.startsWith("/api/oauth2/client")){
				return await OAuthClients.client(request, env);
			} else if(pathname.startsWith("/api/oauth2/authorize")){
				return await OAuthProvider.authorize(request, env, KV);
			} else if(pathname.startsWith("/api/oauth2/token")){
				return await OAuthProvider.token(request, env, KV);
			}
		}

		return new Response("404 Not Found", {
			status: 404,
			headers: {
				'Content-Type' : 'text/plain',
			}
		});
	}
};

// returns true/false. true for being ratelimited, and false when under the limit
const ratelimit = (KV, key, perMinute) => {

	const lookupKey = `Ratelimiter.${key}`;
	let timestamps = KV.get(lookupKey);
	if(!timestamps){
		timestamps = [];
	}
	for(let i = 0; i<timestamps.length; i++){
		if(Date.now() - timestamps[i] > 60 * 1000){
			timestamps.splice(i, 1);
		}
	}

	if(timestamps.length + 1 > perMinute){
		KV.put(lookupKey, timestamps, 60);
		return true;
	}
	timestamps.push(Date.now());
	KV.put(lookupKey, timestamps, 60);
	return false;

}

