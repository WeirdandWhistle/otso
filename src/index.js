/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

const userAgent = "Otso-app";
// OAuth providers to add: gitlab, facebook, bitbucket, yahoo, spotify. all of these might not be free so we'll see...

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

			await env.OAUTH_STATE.put(state, JSON.stringify({auth: provider}), {expirationTtl: 60});
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

			const KVstateTemp = await env.OAUTH_STATE.get(state);
			if(!KVstateTemp)
				return new Response("Invalid State", {status: 400});
			const KVstate = JSON.parse(KVstateTemp);
			
			const body = new URLSearchParams();
			body.set("grant_type", grant_type);
			body.set("code", code);
			body.set("redirect_uri", redirect_uri);
			
			let endpoint;

			if(KVstate.auth == "github"){
				body.set("client_id", env.GITHUB_CLIENT_ID);
				body.set("client_secret", env.GITHUB_CLIENT_SECRET);
				endpoint = githubTokenEndpoint;
			} else if(KVstate.auth == "google"){
				body.set("client_id", env.GOOGLE_CLIENT_ID);
				body.set("client_secret", env.GOOGLE_CLIENT_SECRET);
				endpoint = googleTokenEndpoint;
			} else if(KVstate.auth == "slack"){
				body.set("client_id", env.SLACK_CLIENT_ID);
				body.set("client_secret", env.SLACK_CLIENT_SECRET);
				endpoint = slackTokenEndpoint;
			} else if(KVstate.auth == "discord"){
				body.set("client_id", env.DISCORD_CLIENT_ID);
				body.set("client_secret", env.DISCORD_CLIENT_SECRET);
				endpoint = discordTokenEndpoint;
			} else if(KVstate.auth == "twitch"){
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

			let providerInfo; // {username, id, email}
			
			if(KVstate.auth == "github"){
				providerInfo = await getGithubUser(tokens.access_token);
				providerInfo.email = await getGithubUserEmail(tokens.access_token);
			} else if(KVstate.auth == "google"){
				providerInfo = await getGoogleUser(tokens.access_token);
			} else if(KVstate.auth == "slack"){
				providerInfo = await getSlackUser(tokens);
			} else if(KVstate.auth == "discord"){
				providerInfo = await getDiscordUser(tokens.access_token);
			} else if(KVstate.auth == "twitch"){
				providerInfo = await getTwitchUser(tokens.access_token, env.TWITCH_CLIENT_ID);
				console.log("twitch info",providerInfo);
			}

			return new Response(JSON.stringify(tokens),{
				headers:{
					'Content-Type' : 'application/json'
				}
			});
		}

		return new Response("404 Not Found", {
			status: 404,
			headers: {
				'Content-Type' : 'text',
			}  
		})
	}		
};

async function getGithubUserEmail(access_token){
	const res = await fetch("https://api.github.com/user/emails", {
		headers: {
			'Authorization' : `Bearer ${access_token}`,
			'User-Agent' : userAgent
		}
	});

	if(!res.ok){
		throw new Error("Github API failed while trying to fetch Email. Text: " + await res.text());
	}

	const emailArray = await res.json();
	for(const { primary, email } of emailArray){
		if(primary){
			return email;
		}
	}
}

async function getGithubUser(access_token){
	const res = await fetch("https://api.github.com/user",{
		headers: {
			"Authorization" : `Bearer ${access_token}`,
			"User-Agent" : userAgent
		}
	});

	if(!res.ok)
		throw new Error(`Github /user API failed with code ${res.status}. Text:`, await res.text());
	const json = await res.json();
	// console.log("github /user",json);
	return {
		username: json.login,
		id: json.id
	};
}

async function getGoogleUser(access_token){
	const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
		headers: {
			'Authorization' : `Bearer ${access_token}`,
			'User-Agent' : userAgent
		}
	});

	if(!res.ok){
		throw new Error("Google API failed while trying to fetch Email. Text: " + await res.text());
	}
	const json = await res.json(); 
	console.log("google user info", json);
	return {
		username: json.name,
		email: json.email,
		id: json.sub
	};
}

async function getSlackUser(tokens) {
	const slackInfo = await fetch(`https://slack.com/api/users.info?user=${tokens.authed_user.id}`, {
		headers: {
			'Authorization' : `Bearer ${tokens.access_token}`
		}
	});
	if(!slackInfo.ok)
		throw new Error(`Slack API failed with status ${slackInfo.status}. Text: `+await slackInfo.text());
	const slackJson = await slackInfo.json();
	
	return {
		username: slackJson.user.name,
		id: slackJson.user.id,
		email: slackJson.user.profile.email,
	};
}

async function getDiscordUser(access_token) {
	// console.log("logged in via discord tokens",tokens);
	const discordInfo = await fetch("https://discord.com/api/v10/users/@me",{
		headers:{
			"Authorization":`Bearer ${access_token}`
		}
	});
	if(!discordInfo.ok)
		throw new Error(`Discord API failed with status code ${discordInfo.status}. Text: `+await discordInfo.text());
	const json = await discordInfo.json()
	// console.log("discord info", json);
	return {
		username: json.username,
		id: json.id,
		email: json.email,
	};
}
async function getTwitchUser(access_token, client_id) {
	const twitchInfo = await fetch(`https://api.twitch.tv/helix/users`,{
		headers:{
			"Authorization":`Bearer ${access_token}`,
			"User-Agent": userAgent,
			"Client-Id": client_id
		}
	});
	if(!twitchInfo.ok)
		throw new Error(`Twitch API failed with status code ${twitchInfo.status}. Text: `+await twitchInfo.text());
	let json = await twitchInfo.json();
	console.log("twitch info", json);
	json = json.data[0];
	return {
		username: json.login,
		id: json.id,
		email: json.email,
	};
}



const generateRandomString = (length) => {
  let result = '';
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};
