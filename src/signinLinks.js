import { generateSecureChars } from "./randomData";
import * as session from "./sessions.js";

export const signinLinkPath = '/signin';

export async function getSigninLink(request, env, KV) {
	if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });

    const signinToken = 'sit-' + generateSecureChars(48);

    const search = `via=a&t=${signinToken}`;
    const link = new URL(request.url);
    link.pathname = signinLinkPath;
    link.search = search;

    KV.put('signinlink.a.'+signinToken, user.userID, 10 * 60);
    return new Response(JSON.stringify({
            url: link.toString(),
        }),
        {
            headers:{
                'Content-Type' : 'application/json',
            }
        }
    );
}
export async function getSigninGetSession(request, env, KV) {
    if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });
	if ((await session.useCSRFTokenNoLogin(request, env, KV)) != true) return new Response('401 Unauthorized. CSRFTokenNL is wrong.', { status: 401 });

    const token = new URL(request.url).pathname.split("/")[4];
    if(!token) return new Response('400 Bad Request. token is null somehow..?', { status: 400 });

    const userID = await KV.get('signinlink.a.'+token);
    await KV.remove('signinlink.a.'+token);
    if(!userID) return new Response('401 Unauthorized. Token does not exist.',{status: 401});

    const sessionID = await session.issueSession(env, userID, request.headers);
    return new Response('Session has been issued.',{
        status: 200,
        headers:{
            'Set-Cookie': session.getCookie(sessionID),
        }
    });
}
