import * as db from './databaseInteraction.js';
import * as jwt from './JWT.js';
import { generateRandomString } from './randomData.js';

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
			loadAllKeyPairs(env);
		const out = { keys: [] };
		for(const key of allKeyPairs){
			const temp = await crypto.subtle.exportKey('jwk', key.keypair.publicKey);
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
	if(keypair)
		return keypair;
	if(!allKeyPairs || allKeyPairs.length == 0)
		await loadAllKeyPairs(env);
	if(allKeyPairs.length == 0){
		const kid = "init-key-id";
		const keypair = await jwt.generateKeyPair();
		const pubJWK = await crypto.subtle.exportKey("jwk", keypair.publicKey);
		const secJWK = await crypto.subtle.exportKey("jwk", keypair.privateKey);
		const JWKKeypair = { pub: pubJWK, sec: secJWK };
		await db.createOIDCKey(env, kid, JSON.stringify(JWKKeypair));
		allKeyPairs.push({
			kid: kid,
			keypair: keypair,
			created_at: new Date(),
		});
		// console.log("private1",await crypto.subtle.exportKey("jwk", keypair.privateKey));
		return allKeyPairs[0];
	}
	
	// setTimestampsForKeyPairs();
	sortAllKeys();
	// console.log("keyapris",allKeyPairs[0].created_at);
	if((allKeyPairs[0].created_at.getTime() / 1000) + (60 * 60 * 24) < (Date.now() / 1000))
		await addNewKeyPair(env);
	return allKeyPairs[0];
}
async function addNewKeyPair(env){
	let kid = generateRandomString(8);
	while(true){
		if((await db.getOIDCKeyFromKID(env, kid)) == null) break;
		kid = generateRandomString(8);
	}
	const keypair = await jwt.generateKeyPair();
	await db.createOIDCKey(env, kid, JSON.stringify(keypair));
	await loadAllKeyPairs();
	sortAllKeys();
}
async function loadAllKeyPairs(env){
	allKeyPairs = await db.getAllOIDCKeys(env);
	for(let i = 0; i<allKeyPairs.length;i++){
		// const in1 = allKeyPairs[i].keypair; 
		const { pub, sec } = JSON.parse(allKeyPairs[i].keypair);
		// console.log("pubJWK",pub);
		// console.log("parsed",JSON.parse(allKeyPairs[i].keypair));
		const pubKey = await crypto.subtle.importKey("jwk", pub,{name:"ECDSA", namedCurve:"P-256"},true,["verify"]);
		const secKey = await crypto.subtle.importKey("jwk", sec,{name:"ECDSA", namedCurve:"P-256"},true,["sign"]);
		allKeyPairs[i].keypair = {
			publicKey: pubKey, 
			privateKey: secKey, 
		};
		// console.log(in1,"vs",allKeyPairs[i].keypair);
	}
	setTimestampsForKeyPairs();
}
function setTimestampsForKeyPairs(){
	for(let i = 0; i<allKeyPairs.length;i++){
		allKeyPairs[i].created_at = new Date(allKeyPairs[i].created_at);
		// console.log(`cretae at ${i} `,allKeyPairs[i].created_at);
	}
		
	// console.log("keyapris",allKeyPairs);
}
function sortAllKeys(){
	// console.log("keyapris",allKeyPairs);
	allKeyPairs.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
}
