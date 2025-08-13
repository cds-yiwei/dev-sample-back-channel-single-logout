/*
 MIT License

Copyright (c) 2023 - IBM Corp.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const express = require('express');
const session = require('express-session');
require('dotenv').config();

const { Issuer, generators } = require('openid-client');
const path = require('path');
const app = express();

// Init session
app.use(session({
	secret: 'my-secret',
	resave: true,
	saveUninitialized: false
}));

//middleware
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'front-end'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));


const REDIRECT_URI_PATHNAME = new URL(process.env.REDIRECT_URI).pathname;

// Function for create client 
async function setUpOIDC() {
	let tenantURL = process.env.TENANT_URL;
	if(tenantURL?.endsWith('/')) {
	  tenantURL = `${tenantURL}oauth2/.well-known/openid-configuration`
	} else {
	  tenantURL = `${tenantURL}/oauth2/.well-known/openid-configuration`
	}
	const issuer = await Issuer.discover(tenantURL);
	const client = new issuer.Client({
		client_id: process.env.CLIENT_ID,
		client_secret: process.env.CLIENT_SECRET,
		redirect_uris: process.env.REDIRECT_URI,
		response_typese: process.env.RESPONSE_TYPE
	});

	return client;
}

// Home route
app.get('/', (req, res) => {
	if (req.session.token) {
		res.redirect("/dashboard");
	} else {
		res.render('index')
	}
});

// Login require
// store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// it should be httpOnly (not readable by javascript) and encrypted.

app.get('/login', async (req, res) => {
	const client = await setUpOIDC();
	const url = client.authorizationUrl({
		scope: process.env.SCOPE,
		state: generators.state(),
		redirect_uri: process.env.REDIRECT_URI,
		response_types: process.env.RESPONSE_TYPE,
	});
	res.redirect(url);
});


app.get(REDIRECT_URI_PATHNAME, async (req, res) => {
	const client = await setUpOIDC();
	const params = client.callbackParams(req);
	const tokenSet = await client.callback(process.env.REDIRECT_URI,
		params, { state: req.query.state, nonce: req.session.nonce });
	const userinfo = await client.userinfo(tokenSet.access_token);
	req.session.tokenSet = tokenSet;
	req.session.userinfo = userinfo;
	res.redirect('/dashboard');
});

// Page for render userInfo
app.get('/dashboard', (req, res) => {
	const userinfo = req.session.userinfo;
	const tokenSet = req.session.tokenSet;
	if (!userinfo) {
		return res.redirect('/login');
	}
	res.render('dashboard', { userInfo: userinfo, tokenSet: tokenSet });
});

app.get('/logout', async (req, res) => {
	// import client
	const client = await setUpOIDC();
	// get token from session
	const token = req.session.tokenSet;

	// Get end_session_endpoint from issuer metadata
	const endSessionUrl = client.issuer.metadata.end_session_endpoint;

	// Build logout URL for IdP (Single Logout)
	let logoutUrl = endSessionUrl;
	if (logoutUrl) {
		const params = new URLSearchParams();
		if (token && token.id_token) {
			params.append('id_token_hint', token.id_token);
		}
		params.append('post_logout_redirect_uri', process.env.POST_LOGOUT_REDIRECT_URI);
		logoutUrl += `?${params.toString()}`;
	}

	// Destroy session and redirect to IdP logout
	req.session.destroy(() => {
		if (logoutUrl) {
			res.redirect(logoutUrl);
		} else {
			res.redirect('/');
		}
	});

	// Optionally revoke access token at OP
	 (token && token.access_token) {
		await client.revoke(token.access_token).catch(console.error);
	}if
});

// Back Channel Logout endpoint
app.post('/backchannel_logout', express.json(), async (req, res) => {
	try {
		const client = await setUpOIDC();
		const logoutToken = req.body.logout_token;

		if (!logoutToken) {
			return res.status(400).json({ error: 'logout_token is required' });
		}

		// Validate the logout token
		const valid = await client.validateJWT(logoutToken, {
			audience: process.env.CLIENT_ID,
			typ: 'logout+jwt'
		});

		if (!valid) {
			return res.status(400).json({ error: 'Invalid logout token' });
		}

		// Get the subject (user) from the logout token
		const payload = client.validateIdToken(logoutToken);
		const sub = payload.sub;

		// Destroy all sessions for this user
		// Note: You might need to implement a session store that supports querying by user ID
		// The following is a simple implementation that destroys the current session
		if (req.session.userinfo && req.session.userinfo.sub === sub) {
			req.session.destroy((err) => {
				if (err) {
					console.error('Error destroying session:', err);
				}
			});
		}

		// Return successful response
		return res.status(200).json({ status: 'ok' });
	} catch (error) {
		console.error('Back channel logout error:', error);
		return res.status(500).json({ error: 'Internal server error' });
	}
});



// Listen PORT
app.listen(3000, () => {
	console.log('Server started');
	console.log(`Navigate to http://localhost:3000`);
});
