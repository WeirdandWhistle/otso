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

export default {
	async fetch(request, env, ctx) {
		const pathname = new URL(request.url).pathname;

		const redirect_uri = "http://localhost:8787/callback";
		console.log("not real: ", await env.OAUTH_STATE.get("1234!"));

		if(pathname.startsWith("/oauth/")){
			let forward_url;
			const query = new URLSearchParams();
			const response_type = "code"; query.set("response_type", response_type);
			query.set("redirect_uri", redirect_uri);
			const state = generateRandomString(32); query.set("state", state );

			if(pathname.endsWith("github")){
				forward_url = new URL("https://github.com/login/oauth/authorize");
				const client_id = env.GITUHB_CLIENT_ID; query.set("client_id", client_id);
				await env.OAUTH_STATE.put(state, JSON.stringify({auth:"github"}), {expirationTtl: 60});
			} else if(pathname.endsWith("google")){
				forward_url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
				const client_id = env.GOOGLE_CLIENT_ID; query.set("client_id", client_id);
				query.set("scope", "email profile");
				await env.OAUTH_STATE.put(state, JSON.stringify({auth:"google"}), {expirationTtl: 60});
			}			

			forward_url.search = query.toString();
			return new Response("",{
				status: 302,
				headers: {
					'Location' : forward_url.toString()
				},
			});
		} else if(pathname == "/callback"){
			const githubTokenEndpoint = "https://github.com/login/oauth/access_token";
			const googleTokenEndpoint = "https://oauth2.googleapis.com/token";
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
			}
			
			const res = await fetch(googleTokenEndpoint, {
				method: 'POST',
				headers: {
					'Content-Type' : 'application/x-www-form-urlencoded',
				},
				body: body.toString(),
			});

			// console.log(res);
			const resText = await res.text();

			if(!res.ok){
				return new Response("Sorry, the authorization code exchanged failed :(");
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
			
			if(KVstate.auth == "github"){
				const primaryEmail = getGithubUserEmail(tokens.access_token);
				const username = await getGithubUsername(tokens.access_token);
				console.log("primary email", primaryEmail);
				console.log("username", username);
			} else if(KVstate.auth == "google"){
				const email = await getGoogleEmail(tokens.access_token);
				console.log("google email", email);
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

async function getGithubUsername(access_token){
	const res = await fetch("https://api.github.com/user",{
		headers: {
			"Authorization" : `Bearer ${access_token}`,
			"User-Agent" : userAgent
		}
	});

	if(!res.ok)
		throw new Error(`Github /user API failed with code ${res.status}. Text:`, await res.text());
	const json = await res.json();
	console.log(json);
	return json.login;
}

async function getGoogleEmail(access_token){
	const res = await fetch("https://www.googleapis.com/auth/userinfo.profile", {
		headers: {
			'Authorization' : `Bearer ${access_token}`,
			'User-Agent' : userAgent
		}
	});

	if(!res.ok){
		throw new Error("Google API failed while trying to fetch Email. Text: " + await res.text());
	}

	return await res.text();
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
