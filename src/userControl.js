import * as session from './sessions.js';
import * as db from './databaseInteraction.js';
import { generateRandomString, base64SHA256 } from './randomData.js';

export async function deleteAccount(request, env, KV){
	if(await session.useCSRFToken(request, env, KV) != true)
		return new Response("401 Unauthorized. CSRFToken is wrong.",{status:401});
	const user = await session.getUserIfSession(request, env);
	if(!user)
		return new Response("401 Unauthorized. Session is invalid.",{status:401});
	 if(request.method == 'GET'){
		const url = new URL(request.url);
		const chall = url.searchParams.get("chall").toUpperCase();
		const letter = url.searchParams.get("letter").toUpperCase();
		const enge = generateRandomString(3).toUpperCase();

		if(chall.length != 3 && letter.length != 1)
			return new Response('bad',{status:400});
		 await KV.put(`deleteAccount.${user.userID}`, {challenge: `${chall}${enge}`.toUpperCase(), letter: letter}, 60);
		return new Response(enge);
	 } else if(request.method == 'DELETE'){
		 const nonce = await request.text();
		 if(!nonce)
			 return new Response('bad',{status:400});
		 const data = await KV.get(`deleteAccount.${user.userID}`);
		 if(!data)
			 return new Response('bad',{status:400});
		 const hash = await base64SHA256(data.challenge + '-' + nonce);
		 const l = data.letter;
		 if(hash.startsWith(`${l}${l}${l}`)){
			 await db.deleteUser(env, user.userID);
			 return new Response("consider it done.");
		 }
		 return new Response("**Bugs bunny no face** NO!",{status:400});
	 }
}
