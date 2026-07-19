const userAgent = "Otso-Guardian/1.0 (compatible; Otsobot/1.0; +https://otso.whynotjava.net)";

export async function getGithubUserEmail(access_token){
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

export async function getGithubUser(access_token){
	const res = await fetch("https://api.github.com/user",{
		headers: {
			"Authorization" : `Bearer ${access_token}`,
			"User-Agent" : userAgent
		}
	});

	if(!res.ok)
		throw new Error(`Github /user API failed with code ${res.status}. Text:`, await res.text());
	const json = await res.json();
	// console.log("github /user",json);
	return {
		username: json.login,
		id: json.id,
        issuer: "github",
	};
}

export async function getGoogleUser(access_token){
	const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
		headers: {
			'Authorization' : `Bearer ${access_token}`,
			'User-Agent' : userAgent
		}
	});

	if(!res.ok){
		throw new Error("Google API failed while trying to fetch Email. Text: " + await res.text());
	}
	const json = await res.json();
	return {
		username: json.name,
		email: json.email,
		id: json.sub,
        issuer: "google",
	};
}

export async function getSlackUser(tokens) {
	const slackInfo = await fetch(`https://slack.com/api/users.info?user=${tokens.authed_user.id}`, {
		headers: {
			'Authorization' : `Bearer ${tokens.access_token}`,
			'User-Agent' : userAgent
		}
	});
	if(!slackInfo.ok)
		throw new Error(`Slack API failed with status ${slackInfo.status}. Text: `+await slackInfo.text());
	const slackJson = await slackInfo.json();

	return {
		username: slackJson.user.name,
		id: slackJson.user.id,
		email: slackJson.user.profile.email,
        issuer: "slack",
	};
}

export async function getDiscordUser(access_token) {
	// console.log("logged in via discord tokens",tokens);
	const discordInfo = await fetch("https://discord.com/api/v10/users/@me",{
		headers:{
			"Authorization":`Bearer ${access_token}`,
			"User-Agent" : userAgent,
		}
	});
	if(!discordInfo.ok)
		throw new Error(`Discord API failed with status code ${discordInfo.status}. Text: `+await discordInfo.text());
	const json = await discordInfo.json()
	// console.log("discord info", json);
	return {
		username: json.username,
		id: json.id,
		email: json.email,
        issuer: "discord",
	};
}
export async function getTwitchUser(access_token, client_id) {
	const twitchInfo = await fetch(`https://api.twitch.tv/helix/users`,{
		headers:{
			"Authorization":`Bearer ${access_token}`,
			"User-Agent": userAgent,
			"Client-Id": client_id
		}
	});
	if(!twitchInfo.ok)
		throw new Error(`Twitch API failed with status code ${twitchInfo.status}. Text: `+await twitchInfo.text());
	let json = await twitchInfo.json();
	json = json.data[0];
	return {
		username: json.login,
		id: json.id,
		email: json.email,
        issuer: "twitch",
	};
}
