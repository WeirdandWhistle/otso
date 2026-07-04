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

		if(pathname == "/"){
			const forward_url = new URL("https://github.com/login/oauth/authorize");
			const query = new URLSearchParams();
			const response_type = "code"; query.set("response_type", response_type);
			const client_id = env.CLIENT_ID; query.set("client_id", client_id);
			query.set("redirect_uri", redirect_uri);
			const state = generateRandomString(32); query.set("state", state );
			forward_url.search = query.toString();
			return new Response("",{
				status: 302,
				headers: {
					'Location' : forward_url.toString()
				},
			});
		} else if(pathname == "/callback"){
			const githubTokenEndpoint = "https://github.com/login/oauth/access_token";
			const query = new URL(request.url).searchParams;
			const code = query.get("code");
			const state = query.get("state");
			const grant_type = "authorization_code";
			
			const body = new URLSearchParams();
			body.set("grant_type", grant_type);
			body.set("code", code);
			body.set("redirect_uri", redirect_uri);
			body.set("client_id", env.CLIENT_ID);
			body.set("client_secret", env.CLIENT_SECRET);

			const res = await fetch(githubTokenEndpoint, {
				method: 'POST',
				headers: {
					// 'Authorization' : `Basic ${env.CLIENT_SECRET}`,
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

			// console.log("tokens",tokens);
			console.log("email",await listGithubUserEmails(tokens.access_token));

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

async function listGithubUserEmails(access_token){
	const res = await fetch("https://api.github.com/user/emails", {
		headers: {
			'Authorization' : `Bearer ${access_token}`,
			'User-Agent' : userAgent
		}
	});

	if(!res.ok){
		throw new Error("Github API failed while trying to fetch Email. Text: " + await res.text());
	}

	return await res.json();
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
