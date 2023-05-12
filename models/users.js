const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
	username: {
		type: String,
		required: true, // this field is required
		unique: true, // this field should be unique
	},
	password: {
		type: String,
		required: true,
	},
	admin: {
		type: Boolean,
		default: false, // default value is false
	},
});

module.exports = mongoose.model('User', userSchema);
