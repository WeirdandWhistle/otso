import { getGithubUserEmail, getGithubUser, getGoogleUser, getSlackUser, getDiscordUser, getTwitchUser } from "./getUserData.js";
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';
import * as db from "./databaseInteraction.js";
import * as session from "./sessions.js";

export async function linkAccounts(request, env, KV) {

}
