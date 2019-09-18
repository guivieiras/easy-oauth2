class OauthError extends Error {
	constructor({ error, errorDescription, redirectUri }) {
		super(error)
		this.error = error
		this.errorDescription = errorDescription
		this.redirectUri = redirectUri
	}
}
export default OauthError
