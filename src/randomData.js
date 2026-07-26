import crypto from 'crypto';

export const base64SHA256 = async (text) => {
	let buffer = new TextEncoder().encode(text).buffer;
	buffer = await crypto.subtle.digest("SHA-256", buffer);
	return new Uint8Array(buffer).toBase64({alphabet: "base64url", omitPadding: true});
}
export const generateRandomString = (length) => {
  let result = '';
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};
export const generateUserID = () => {
	return generateSecureChars(42);
};
export const allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_. ";

export const usernameMaxLength = 100;
export const validUsername = (username) => {
	if(username.length <= 0 || username.length > usernameMaxLength)
		return false;
	if(username != username.trim())
			return false;
	for(let i = 0; i<username.length;i++){
		if(!allowedChars.includes(username.charAt(i))){
			return false;
		}
	}
	return true;
}
export const correctUsername = (username) => {
	let res = '';
	if(username.length <= 0){
		for(let i = 0; i < 15; i++){
			res += allowedChars.charAt(Math.floor(Math.random() * allowedChars.length));
		}
		return res;
	} else if(username.length > usernameMaxLength){
		username = username.sub(0, usernameMaxLength-1);
	}

	for(let i = 0; i<username.length;i++){
		if(allowedChars.includes(username.charAt(i))){
			res += username.charAt(i);
		}
	}
	if(res.length <= 0){
		for(let i = 0; i < 15; i++){
			res += allowedChars.charAt(Math.floor(Math.random() * allowedChars.length));
		}
		return res;
	}
	return res;
}
export const generateSecureChars = (length) => {
	const buf = new Uint8Array(length+1);
	crypto.getRandomValues(buf);
	return buf.toBase64({alphabet: "base64url", omitPadding: true}).substring(0,length-1);
};
export const generateClientSecret = ()=>{
	return "shh-" + generateSecureChars(16) + "-" + generateSecureChars(16);
}
export const generateAccessToken = ()=>{
	return generateSecureChars(32);
}
export const generateRefreshToken = ()=>{
	return generateSecureChars(64);
}
export const safeCompareString = (a, b)=>{
	const bufA = Buffer.from(a);
	const bufB = Buffer.from(b);
	return crypto.timingSafeEqual(bufA, bufB);
}
