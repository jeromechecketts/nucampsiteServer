const { appSecret } = require('./secrets.js');

module.exports = {
	secretKey: '12345-67890-09876-54321',
	mongoUrl: 'mongodb://localhost:27017/nucampsite',
	facebook: {
		clientId: '170316419035145',
		clientSecret: appSecret,
	},
};
