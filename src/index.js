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
import * as db from "./databaseInteraction.js";

export default {
	async fetch(request, env, ctx) {
		const pathname = new URL(request.url).pathname;

		const redirect_uri = "http://localhost:8787/callback";

		if(pathname.startsWith("/oauth/")){
			let forward_url;
			const query = new URLSearchParams();
			const response_type = "code"; query.set("response_type", response_type);
			query.set("redirect_uri", redirect_uri);
			const state = generateRandomString(32); query.set("state", state );
			let client_id;
			let provider;

			if(pathname.endsWith("github")){
				forward_url = new URL("https://github.com/login/oauth/authorize");
				client_id = env.GITHUB_CLIENT_ID;
				provider = "github";
			} else if(pathname.endsWith("google")){
				forward_url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
				client_id = env.GOOGLE_CLIENT_ID;
				query.set("scope", "email profile");
				provider = "google";
			} else if(pathname.endsWith("slack")){
				forward_url = new URL("https://slack.com/oauth/v2/authorize");
				client_id = env.SLACK_CLIENT_ID;
				query.set("scope", "users:read");
				provider = "slack";
			} else if(pathname.endsWith("discord")){
				forward_url = new URL("https://discord.com/oauth2/authorize");
				client_id = env.DISCORD_CLIENT_ID;
				query.set("scope", "identify email");
				provider = "discord";
			} else if(pathname.endsWith("twitch")){
				forward_url = new URL("https://id.twitch.tv/oauth2/authorize");
				client_id = env.TWITCH_CLIENT_ID;
				query.set("scope", "user:read:email");
				provider = "twitch";
			} else {
				throw new Error("That OAuth 2.0 provider is currently not supported");
			}

			// await env.OAUTH_STATE.put(state, JSON.stringify({auth: provider}), {expirationTtl: 60});
			await db.oauthStatePut(env, state, JSON.stringify({auth: provider}));
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
			const OAuthStateTemp = await db.oauthStateGet(env, state);
			if(!OAuthStateTemp)
				return new Response("Invalid State", {status: 400});
			const OAuthState = JSON.parse(OAuthStateTemp);
			
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

			const user = await db.getUser(env, issuerInfo.id, issuerInfo.issuer);
			console.log("after authed: user from db, ", user);
			if(!user){
				
				OAuthState.issuerInfo = issuerInfo;
				db.oauthStatePut(state, JSON.stringify(OAuthState));

				const sp = new URLSearchParams();
				sp.set("state", state);
				sp.set("username", issuerInfo.username);
				sp.set("email", issuerInfo.email);

				// const redirectURL = new URL("/firstTime");
				// redirectURL.search = sp.toString;

				const toURL = "/firstTime?" + sp.toString();

				return new Response("You are currently being redirected to "+toURL,{
					status: 302,
					headers: {
						"Location" : toURL
					}
				});
			} else {
				console.log("How to fu\n what ever. my first wish is to have...");
			}
			

			db.oauthStateDelete(env, state);
			return new Response(JSON.stringify(issuerInfo),{
				headers:{
					'Content-Type' : 'application/json'
				}
			});
		}

		if(pathname.startsWith("/api/")){
			if(pathname.endsWith("/createAccount") && request.method == 'POST'){

			}
		}

		return new Response("404 Not Found", {
			status: 404,
			headers: {
				'Content-Type' : 'text',
			}
		});
	}		
};

const generateRandomString = (length) => {
  let result = '';
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};
