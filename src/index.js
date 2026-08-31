const userAgent = 'Otso-Guardian/1.0 (compatible; Otsobot/1.0; +https://otso.whynotjava.net)';
// OAuth providers to add: gitlab, facebook, bitbucket, yahoo, spotify. all of these might not be free so we'll see...

import * as APIHandler from './APIHandler.js';
import * as databaseInitializer from './databaseInitialization.js';

let databaseInitialized = false;
let deleteDatabaseOnStart = false;

export default {
	async fetch(request, env, ctx) {
		if (!databaseInitialized) {
			// console.log("init database");
			if (deleteDatabaseOnStart) {
				// console.log("delete database")
				await databaseInitializer.remove(env);
				deleteDatabaseOnStart = false;
			}
			await initializeDatabase(env);
		}

		const logging = env.EXTENSIVE_LOGGING == 'true';
		let req;
		if (logging) {
			req = request.clone();
		}

		const response = await APIHandler.handle(request, env);

		if (logging) {
			const res = response.clone();
			let requestBody = null;
			let method = req.method;
			if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') requestBody = await req.text();

			let responseBody = await res.text();

			console.log(
				'inconing request:',
				{
					url: req.url,
					method: req.method,
					headers: req.headers.values(),
					body: requestBody,
				},
				'\n',
				'outgoing response:',
				{
					status: res.status,
					headers: res.headers.values(),
					body: responseBody,
				},
			);
		}
		return response;
	},
};

async function initializeDatabase(env) {
	await databaseInitializer.init(env);
	databaseInitialized = true;
}
