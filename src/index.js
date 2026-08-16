const userAgent = 'Otso-Guardian/1.0 (compatible; Otsobot/1.0; +https://otso.whynotjava.net)';
// OAuth providers to add: gitlab, facebook, bitbucket, yahoo, spotify. all of these might not be free so we'll see...

import * as APIHandler from './APIHandler.js';
import * as databaseInitializer from './databaseInitialization.js';

let databaseInitialized = false;
let deleteDatabaseOnStart = false;

export default {
	async fetch(request, env, ctx) {
		if (!databaseInitialized) {
			console.log("init database");
			if(deleteDatabaseOnStart){
				console.log("delete database")
				await databaseInitializer.remove(env);
				deleteDatabaseOnStart = false;
			}
			await initializeDatabase(env);
		}

		return await APIHandler.handle(request, env);
	},
};

async function initializeDatabase(env) {
	await databaseInitializer.init(env);
	databaseInitialized = true;
}