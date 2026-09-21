import { generateSecureChars } from './randomData';
import * as session from './sessions.js';

export const signinLinkPath = '/s';
export const signinLinkTokenLength = 16;

export async function getSigninLink(request, env, KV) {
	if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });

	const signinToken = 'sit-' + generateSecureChars(signinLinkTokenLength); // (sit) sign in token

	const search = `v=a&t=${signinToken}`;
	const link = new URL(request.url);
	link.pathname = signinLinkPath;
	link.search = search;

	await KV.put('signinlink.a.' + signinToken, user.userID, 10 * 60);
	return new Response(
		JSON.stringify({
			url: link.toString(),
		}),
		{
			headers: {
				'Content-Type': 'application/json',
			},
		},
	);
}
export async function getSigninGetSession(request, env, KV) {
	if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFTokenNoLogin(request, env, KV)) != true)
		return new Response('401 Unauthorized. CSRFTokenNL is wrong.', { status: 401 });

	const token = new URL(request.url).pathname.split('/')[4];
	if (!token) return new Response('400 Bad Request. token is null somehow..?', { status: 400 });

	const userID = await KV.get('signinlink.a.' + token);
	await KV.remove('signinlink.a.' + token);
	if (!userID) return new Response('401 Unauthorized. Token does not exist.', { status: 401 });

	const sessionID = await session.issueSession(env, userID, request.headers);
	return new Response('Session has been issued.', {
		status: 200,
		headers: {
			'Set-Cookie': session.getCookie(sessionID),
		},
	});
}
export async function getWebsocket(request, env, KV) {
	const upgradeHeader = request.headers.get('Upgrade');
	if (!upgradeHeader || upgradeHeader !== 'websocket') {
		return new Response('Expected Upgrade: websocket', { status: 426 });
	}

    const CSRFTokenNL = new URL(request.url).searchParams.get("CSRFTokenNL");
    if(!session.useCSRFTokenNoLogin(request, env, KV, CSRFTokenNL)) return new Response("401 Unauthorized. CSRFTokenNL is wrong.", { status:401 });

	const token = 'apt-' + generateSecureChars(signinLinkTokenLength); // (apt) approve token

    let stub = env.SIGNIN_LINK_WEBSOCKET.getByName(`do-${token}`);
    console.log('stub');
    // console.log(stub.loadWebsocket(request, token));
    const headers = new Headers(request.headers);
    headers.set("token", token);
    return await stub.fetch(request.url, {
        method: request.method,
        headers: headers,
        body: request.body,
    });
}
export async function getMetadata(request, env, KV){
    if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true)
		return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
    const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });
    const token = new URL(request.url).pathname.split('/')[4];
	if (!token) return new Response('400 Bad Request. token is null somehow..?', { status: 400 });

    let stub = env.SIGNIN_LINK_WEBSOCKET.getByName(`do-${token}`);
    const metadata = await stub.reportMetadata();
    metadata.username = user.username;

    return new Response(JSON.stringify(metadata));
}
export async function approve(request, env, KV) {
    if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true)
		return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
    const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });
    const token = new URL(request.url).pathname.split('/')[4];
	if (!token) return new Response('400 Bad Request. token is null somehow..?', { status: 400 });

    const approvedToken = 'dot-' + generateSecureChars(32); // (adt) almost done token
    await KV.put('signinlink.a.'+approvedToken, user.userID, 30);
    let stub = env.SIGNIN_LINK_WEBSOCKET.getByName(`do-${token}`);
    await stub.approved(approvedToken);
    await stub.selfDestruct();
    return new Response('HFS that took a long time... WAIT WERE NOT FUCKING DONE! :('); 
}
export async function deny(request, env, KV) {
    if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true)
		return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
    const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });
    const token = new URL(request.url).pathname.split('/')[4];
	if (!token) return new Response('400 Bad Request. token is null somehow..?', { status: 400 });
    let stub = env.SIGNIN_LINK_WEBSOCKET.getByName(`do-${token}`);
    await stub.deny();
    await stub.selfDestruct();
    return new Response('HAHA after all that you still failed !'); 
}

import { DurableObject } from "cloudflare:workers";
var platform = require('platform');
export class WebSocketDurableObject extends DurableObject {
    constructor(ctx, env, token){
        super(ctx, env);
        this.token = token;
        this.ctx.setWebSocketAutoResponse(
            new WebSocketRequestResponsePair("ping", "pong")
        )
    }
    async fetch(request){
        try {
        await this.ctx.storage.put("token", request.headers.get("token"));
        
        if(request.headers.get("User-Agent")){
            const md = platform.parse(request.headers.get('User-Agent'));
            console.log('md',md);
            await this.ctx.storage.put("ip", request.headers.get("CF-Connecting-IP"));
            await this.ctx.storage.put("browser", md.name);
            await this.ctx.storage.put("os", md.os.family);
        } else {
            console.log('hearders', request.headers);
        }
        await this.ctx.storage.put("origin", new URL(request.url).origin);
        const webSocketPair = new WebSocketPair();
	    const [client, server] = Object.values(webSocketPair);

        this.ctx.acceptWebSocket(server);
            console.log('retutning websocket fr');
	    return new Response(null, {
	    	status: 101,
	    	webSocket: client,
	    });
        } catch (error) {
            console.log('err',error);
        }
        
    }
    async reportMetadata(){
        return { ip: await this.ctx.storage.get("ip"), os: await this.ctx.storage.get("os"), browser: await this.ctx.storage.get("browser"), };
    }
    async webSocketMessage(ws, message){
        const data = JSON.parse(message);
        switch(data.type){
            case "getSigninLink":
                ws.send(`{"type":"signinLink","url":"${await this.ctx.storage.get("origin")}${signinLinkPath}?v=b&t=${await this.ctx.storage.get("token")}"}`);
                break;
        }
    }
    async approved(token){
        this.ctx.getWebSockets()[0].send(JSON.stringify({
            type:'approved',
            token: token,
        }));
    }
    async deny(){
        this.ctx.getWebSockets()[0].send(JSON.stringify({
            type:'denied',
        }));
    }
    async selfDestruct(){
        await this.ctx.storage.deleteAll();
        this.ctx.getWebSockets().forEach((ws)=>ws.close(1000, `{"type":"close"}`));
    }
}
