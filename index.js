import crypto from 'crypto'
import moment from 'moment'
import axios from 'axios'

export default class {
	constructor(app) {
		this.app = app

		app.get('/register-application', this.registerApplicationHandler.bind(this))
		app.post('/authorize', this.authorization.bind(this))
		app.post('/token', this.token.bind(this))
	}

	async registerApplicationHandler(req, res, next) {
		//TODO Need to be authenticated
		let { name, logo, redirectURI, userId, website } = req.body
		await this.registerApplication({ name, logo, redirectURI, userId, website })
		res.send('Success!')
	}

	async authorization(req, res, next) {
		let { client_id, scope, state, response_type, redirect_uri } = req.body
		let userId = 'user123' //TODO Get from somewhere cookies or auth headers, this can go to the example app

		let application = await this.getApplication(client_id)
		if (!application) {
			return res.status(400).send('Client not found')
		}

		let user = await this.getUser(userId)
		if (!user) {
			return res.status(400).send('User not found')
		}

		if (application.redirectURI !== redirect_uri) {
			return res.status(400).send('Redirect URI mismatch!')
		}
		if (response_type === 'code') {
			let code = await this.generateAuthorizationCode({ userId, clientId: application.clientId, scope })

			return res.redirect(application.redirectURI + '?' + serialize({ code, state }))
		} else {
			return res.status(400).redirect(application.redirectURI + '?error=Response type not found')
		}
	}

	async generateAuthorizationCode({ clientId, userId, scope }) {
		let code = 'smash_authorization_code_' + 'fixo' //crypto.randomBytes(32).toString('hex')

		this.saveAuthorizationCode({ code, clientId, userId, scope })
		return code
	}

	async generateAccessToken({ application, clientId, scope }) {
		let accessToken = 'smash_access_token_' + crypto.randomBytes(32).toString('hex')
		let accessTokenExpiresOn = moment().add(1, 'hour')
		let refreshToken = 'smash_refresh_token_' + crypto.randomBytes(32).toString('hex')
		let refreshTokenExpiresOn = moment().add(30, 'days')
		let userId = application.userId

		let obj = { accessToken, accessTokenExpiresOn, refreshToken, refreshTokenExpiresOn, clientId, userId, scope }
		return this.saveAccessToken(obj)
	}

	async token(req, res, next) {
		let { grant_type } = req.body

		if (grant_type === 'authorization_code') {
			let { code, client_id } = req.body
			let application = await this.getApplication(client_id)
			if (!application) {
				return res.status(400).send('Client not found')
			}

			let authorizationCode = await this.getAuthorizationCode(code)
			if (!authorizationCode) {
				return res.status(400).send('Authorization code not found')
			}

			let accessToken = await this.generateAccessToken({ application, clientId: client_id })
			return res.send(accessToken)
		}
		if (grant_type === 'password') {
			let { username, password } = req.body
			let result = await this.verifyUsernameAndPassword(username, password)
			if (!result) {
				return res.status(400).send('User not found or password invalid')
			}

			let accessToken = await this.generateAccessToken({ application, clientId: client_id })
			return res.send('TODO')
		}
		if (grant_type === 'client_credentials') {
			let { client_secret, client_id } = req.body
			if (application.clientSecret !== client_secret) {
				return res.status(400).send('Secret mismatch')
			}
		}
		if (grant_type === 'refresh_token') {
			let { refresh_token } = req.body
			let authorizationCode = await this.getAccessTokenByRefreshToken(refresh_token)
			if (!authorizationCode) {
				return res.status(400).send('Authorization code not found')
			}
		}
	}

	/**
	 * @param {Object} application - The employee who is responsible for the project.
	 * @param {string} application.name - The name of the employee.
	 * @param {string} application.website - The employee's department.
	 * @param {string} application.logo - The employee's department.
	 * @param {string} application.redirectURI - The employee's department.
	 * @param {string} application.userId - The employee's department.
	 */
	async registerApplication({ name, website, logo, redirectURI, userId }) {
		let clientID = 'smash_client_id_' + 'fixo' //crypto.randomBytes(32).toString('hex')
		let clientSecret = 'smash_client_secret_' + 'fixo' //crypto.randomBytes(32).toString('hex')

		this.verifyIfRedirectUriIsValid(redirectURI)

		await this.saveApplication({ name, website, logo, redirectURI, userId, clientID, clientSecret })
	}

	verifyIfRedirectUriIsValid(redirectURI) {
		let reg = /.+:\/\/.+/
		if (!reg.test(redirectURI)) {
			throw new Error('Invalid uri') //TODO implementar maybe not 404 on get
		}
	}

	initViews() {
		this.app.get('/authorize-frontend', [
			this.authenticatedMiddleware.bind(this),
			this.renderAuthorizationView.bind(this)
		])
	}

	async authenticatedMiddleware(req, res, next) {
		if (req.query.logged !== 'yes') {
			return next()
		}
		res.status(400).send('Not authenticated')
	}

	// Must implement

	async saveApplication({ name, website, logo, redirectURI, userId, clientId, clientSecret }) {
		throw new Error('Must implement')
	}

	async getApplication(clientID) {
		throw new Error('Must implement')
	}

	async saveAccessToken({
		accessToken,
		accessTokenExpiresOn,
		refreshToken,
		refreshTokenExpiresOn,
		clientId,
		userId,
		scope
	}) {
		throw new Error('Must implement')
	}

	async saveAuthorizationCode({ code, clientId, userId, scope }) {
		throw new Error('Must implement')
	}

	async getAuthorizationCode(code) {
		throw new Error('Must implement')
	}

	async renderAuthorizationView() {
		throw new Error('Must implement')
	}

	async verifyUsernameAndPassword(username, password) {
		throw new Error('Must implement')
	}

	async getDevUser(devUserId) {
		throw new Error('Must implement')
	}

	async getUser(userId) {
		throw new Error('Must implement')
	}

	async getAccessTokenByRefreshToken(refreshToken) {
		throw new Error('Must implement')
	}
}

function serialize(obj) {
	var str = []
	for (var p in obj) {
		if (obj.hasOwnProperty(p)) {
			str.push(encodeURIComponent(p) + '=' + encodeURIComponent(obj[p]))
		}
	}
	return str.join('&')
}
