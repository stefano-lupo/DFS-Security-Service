let mongoose = require('mongoose');
let bcrypt = require('bcrypt-nodejs');


// Define fields
let clientSchema = mongoose.Schema(
  {
    name: String,
    email: String,
    password: String,
    lastLogIn: Date,
    clientKey: String
  },
  {
    timestamps: true
  }
);

// Define methods
clientSchema.methods.isValidPassword = function(password) {
  console.log(`Checking ${password} against ${this.password}`);
  return bcrypt.compareSync(password, this.password)
};

clientSchema.methods.hash = data => {
  return bcrypt.hashSync(data);
};

// Compile schema into model BEFORE compilation
let Client = mongoose.model('Client', clientSchema);



module.exports = {
  Client,
};
