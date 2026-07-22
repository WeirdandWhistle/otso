export function parseScopes(authorizedApps){
	const apps = authorizedApps.split(" ");
	const outMap = new Map();
	for(const app of apps){
		const appArray = app.split(";");
		const appID = appArray[0];
		if(!appID)
			break;
		appArray.shift();
		const scopeSet = new Set();
		for(const scope of appArray){
			scopeSet.add(scope);
		}
		outMap.set(appID, scopeSet);
	}
	return outMap;
}
export function stringifyScopes(inMap){
	let res = '';
	inMap.forEach((value, key)=>{
		let packedScopes = '';
		value.forEach((value)=>packedScopes += `;${value}`);
		res += key + packedScopes + ' ';
	});
	return res.trim();
	;
}
