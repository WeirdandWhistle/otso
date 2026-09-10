import {
	base64url,
	validUsername,
	correctUsername,
	base64SHA256,
	generateRandomString,
	generateSecureChars,
	generateAccessToken,
	generateRefreshToken,
	safeCompareString,
} from './randomData.js';
import crypto from 'crypto';

export const signingAlg = 'ES256';
export const JWTType = 'JWT';
export const JOSEHeader = {
	alg: signingAlg,
	typ: JWTType,
};

export function generatePayload(issuer, userID, audience, experationTime, notBefore, nonce, claims) {
	let currentUnixTimestamp = Math.floor(Date.now() / 1000);
	if (currentUnixTimestamp == null) throw new Error('The time can not be null?!?!?!');
	let payload = {
		iss: issuer,
		sub: userID,
		aud: audience,
		exp: Math.floor(experationTime),
		nbf: Math.floor(notBefore),
		iat: currentUnixTimestamp,
		auth_time: currentUnixTimestamp,
		jti: generateSecureChars(32),
		nonce: nonce ? nonce : generateRandomString(16),
	};
	for (const key in claims) {
		// console.log("claim",key,"value",claims[key]);
		payload[key] = claims[key];
	}
	// console.log("payload",payload);
	return payload;
}
export async function generateSignaute(header, payload, key) {
	const sign = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
	const temp = await crypto.subtle.sign(
		{
			name: 'ECDSA',
			hash: { name: 'SHA-256' },
		},
		key,
		new TextEncoder().encode(sign).buffer,
	);
	const arr = new Uint8Array(temp);
	return arr.toBase64({ alphabet: 'base64url', omitPadding: true });
}
export function encodeFullJWT(header, payload, signature) {
	return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.${signature}`;
}
export async function generateKeyPair() {
	return await crypto.subtle.generateKey(
		{
			name: 'ECDSA',
			namedCurve: 'P-256',
		},
		true,
		['sign', 'verify'],
	);
}
