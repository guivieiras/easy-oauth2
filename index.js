import crypto from 'crypto'
export default class {
	constructor(app) {
		this.app = app

		app.get('/register-application', this.registerApplicationHandler.bind(this))
		app.get('/authorize-frontend')
	}

	async registerApplicationHandler(req, res, next) {
		await this.registerApplication({
			name: 'New Used Media',
			logo: 'https://dev.newusedmedia.com/static/media/logo_white.e0ee2117.png',
			redirectURI: 'http://localhost:2000/auth/smash/callback',
			userId: 123,
			website: 'www.newusedmedia.com'
		})
		res.send('Success!')
	}

	async token(req, res, next) {
		console.log('chamou')
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
		let clientID = 'smash_client_id_' + crypto.randomBytes(10).toString('hex')
		let clientSecret = 'smash_client_secret_' + crypto.randomBytes(10).toString('hex')

		this.verifyIfRedirectUriIsValid(redirectURI)

		await this.saveApplication({ name, website, logo, redirectURI, userId, clientID, clientSecret })
	}

	verifyIfRedirectUriIsValid(redirectURI) {
		if (false) {
			throw new Error('Must implement error verification') //TODO implementar
		}
	}

	async saveApplication({ name, website, logo, redirectURI, userId, clientID, clientSecret }) {
		throw new Error('Must implement')
	}

	async renderAuthorizationView() {
		throw new Error('Must implement')
	}

	initViews() {
		this.app.get('/authorize-frontend', [
			this.authenticatedMiddleware.bind(this),
			this.renderAuthorizationView.bind(this)
		])
	}

	async authenticatedMiddleware(req, res, next) {
		if (req.query.logged === 'yes') {
			return next()
		}
		res.status(400).send('Not authenticated')
	}
}
