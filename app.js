//jshint esversion:6

    //Server SetUp --->
require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const passport= require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const user = require(__dirname+"/user.js");
const userNameDB = process.env.DB_USER;
const password = process.env.DB_PASS;
const cluster = process.env.DB_CLUSTER;
const eKey = process.env.ENCKEY;
const secretString = process.env.SECRET_STRING;
const app = express();
let port = process.env.PORT;

if(port==null || port==""){
  port = 5000;
}

app.listen(port, function(){
  console.log("Server running on port: "+port);
});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret:secretString,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


////Database Configuration -->
const remoteUrl = 'mongodb+srv://'+userNameDB+':'+password+cluster+'.mongodb.net/';
const dbName = "blogUserDB";

const remoteDbUrl = remoteUrl+dbName;

mongoose.connect(remoteDbUrl, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);


//Configuration of PassportJs
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://pbarbeiro-secrets.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log("profile log: ");
    //console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      console.log("App reached passport.use GoogleStrategy");
      return cb(err, user);
    });
  }
));

////API code --->

app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");

});

app.get("/secrets", function(req, res){
  User.find({}, {secret:1}, function(err, foundUsers){
    if(!err){
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }else{
      res.redirect("/");
      console.log("Secrets - Get Route - Error while finding users w/ secrets: ");
      console.log(err);
    }
  });

});


///Submit Route
app.route("/submit")

  .get(function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
  })

  .post(function(req, res){
    //console.log(req);
    User.findById({_id: req.user.id}, function(err, userFound){
      if(!err){
        if(userFound){
          userFound.secret = req.body.secret;
          userFound.save(function(){
            res.redirect("/secrets");
          });
        }

      } else{
        console.log("Submit - POST route - There was an error while finding the user: ");
        console.log(err);
      }
    });
  });


///Register Route
app.route("/register")

  .get(function(req, res){
    res.render("register");
  })

  .post(function(req, res){
    const password = req.body.password;
    const email = req.body.username;

    // console.log("Username/email: %o", email);
    // console.log("Password: %o", password);

    User.register({username: email},  password, function(err, user){
      if(!err){
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });

        console.log("Response from cb - user: ");
        console.log(user);
      } else{
        console.log("Error while registering user: %o", err);
        res.redirect("/register");
      }
    });

});


///Login Route
app.route("/login")

.get(function(req, res){
  res.render("login");
})

.post(function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(!err){
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }else{
      console.log("Err while logging user: %o", user.username);
      console.log(err);
    }
  });


});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});


/*TODO:
  0.
  1. If a user has already been registered, he should not be able to register again
  2. Prepare the code to give feedback on user email ( if one is already found in db while registering)
  3. Automate the adding of a numeric id
  4. Repeat 1 & 2 for login process?
  5.
  6.
  7. Add the funcitonality to add more than one Secret.
  8. Add the funcitonality to delete your previous posts.

*/
