import * as db from './databaseInteraction.js';
import * as jwt from './JWT.js';


let allKeyPairs = null;

export async function endpoint(request, env, KV) {
    const pathname = new URL(request.url).pathname;
	if (pathname.startsWith('/.well-known/openid-configuration')) {
		const origin = new URL(request.url).origin;
		const out = {
			issuer: origin,
			authorization_endpoint: `${origin}/api/oauth2/authorize`,
			token_endpoint: `${origin}/api/oauth2/token`,
			userinfo_endpoint: `${origin}/api/account/info`,
			jwks_uri: `${origin}/.well-known/jwks.json`,
			response_types_supported: ['code', 'token', 'id_token'],
			id_token_signing_alg_values_supported: ['ES256'],
			scopes_supported: ['username', 'email', 'id', 'openid', 'profile'],
			token_endpoint_auth_methods_supported: ['client_secret_basic'],
		};
		return new Response(JSON.stringify(out), {
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': '*',
			},
		});
	} else if (pathname.startsWith('/.well-known/jwks.json')) { // http://localhost:8787/.well-known/jwks.json
		if(!allKeyPairs || allKeyPairs.length == 0)
			loadAllKeyParis(env);
		const out = { keys: [] };
		for(const key of keys){
			const temp = await crypto.subtle.exportKey('jwk', key);
			temp.kid = key.kid;
			out.keys.push(temp);
		}
		
		return new Response(JSON.stringify(out),{
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': '*',
				'Cache-Control':`max-age=${60 * 60 * 3}`,
			},
		})
	}
}

export async function getActiveKeypair(env, keypair){
	console.log("allKeyPairs",allKeyPairs);
	if(keypair)
		return keypair;
	if(!allKeyPairs || allKeyPairs.length == 0)
		loadAllKeyParis(env);
	if(allKeyPairs.length == 0){
		const kid = "init-key-id";
		const keypair = JSON.stringify(await jwt.generateKeyPair());
		await db.createOIDCKey(kid, keypair);
		allKeyPairs.push({
			kid: kid,
			keypair_json: keypair,
			created_at: new Date(),
		});
		return allKeyPairs[0];
	}
	allKeyPairs.sort((a, b) => b.created_at.toTime() - a.created_at.toTime());
	return allKeyPairs[0];
}

async function loadAllKeyParis(env){
	allKeyPairs = await db.getAllOIDCKeys(env);
}
