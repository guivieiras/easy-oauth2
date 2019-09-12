// index.mjs

export default function (app) {
	app.use(token)
}

const vaer = function() {}

function token(req, res, next) {}

export function bar() {
	console.log('This is ESM!')
}

export const someValue = 12

export default {
	foo,
	bar,
	someValue
}
