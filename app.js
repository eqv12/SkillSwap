import express, { json, urlencoded } from "express";
import { connect } from "mongoose";
import { User } from "./models/User.js";
// import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import { Skill } from "./models/Skills.js";
import { Request } from "./models/Request.js";
import Counter from "./models/Counter.js";
import connectDB from "./db.js";
import { getNextSequence } from "./utilities/getNextSequence.js";
import nodemailer from "nodemailer";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
// import { sendEmail } from './mailer.js';
import crypto from "crypto";
import { title } from "process";

const pendingUsers = {};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "anony3938@gmail.com",
    pass: "bbyi yuej ceni huaa",
  },
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;
connectDB();
// const dbURI =
//   "mongodb+srv://ramya:Wimmss123.@dev-skill-swap-cluster.efbjn.mongodb.net/skillSwap?retryWrites=true&w=majority&appName=dev-skill-swap-cluster";

// connect(dbURI)
//   .then(() => console.log("Connected to MongoDB"))
//   .catch((err) => console.error("MongoDB connection error", err));

app.use(express.static("public"));
app.use(cookieParser());

// app.use(cors());
app.use(json());
app.use(urlencoded({ extended: true }));

app.use(passport.initialize());

passport.use(
  new GoogleStrategy(
    {
      clientID: "1096054788985-31ei5n0viof5b4rscl7a6eb0mco4vilo.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.name.familyName;
        const rollno = email.split("@")[0].toUpperCase();
        const usercheck = await User.findOne({ rollno: rollno });
        if (usercheck) {
          return done(null, false);
        }
        // console.log(name);
        if (!email.endsWith("@psgtech.ac.in")) {
          return done(null, false);
        }
        const token = jwt.sign({ name, email, is_verified: true, purpose: "signup" }, "ramya-preethinthran-sharun", {
          expiresIn: "10m",
        });
        console.log("google token successfuly passed to req.user", token);
        done(null, token); // Pass the token as the user object
      } catch (err) {
        return done(err, false);
      }
    }
  )
);
//the one blow is for password reset.
passport.use(
  "google-password-reset",
  new GoogleStrategy(
    {
      clientID: "1096054788985-31ei5n0viof5b4rscl7a6eb0mco4vilo.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/password-reset-callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const rollno = email.split("@")[0].toUpperCase();
        const name = profile.name.familyName;
        const user = await User.findOne({ rollno: rollno });

        if (!user || !email.endsWith("@psgtech.ac.in")) {
          return done(null, false);
        }

        const token = jwt.sign({ name, rollno, email, purpose: "password_reset" }, "ramya-preethinthran-sharun", {
          expiresIn: "10m",
        });
        console.log("Password reset token generated", token);

        done(null, token); // Pass the token to the flow
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

//these are the middlewares.
const generateToken = (rollno, expiresIn = "15m") => {
  return jwt.sign({ rollno, purpose: "access" }, "ramya-preethinthran-sharun", { expiresIn });
};
//token authentication middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.redirect("http://localhost:3000/login?message=Invalid+or+missing+token.+Please+login+again.");
  }

  try {
    const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
    if (decoded.purpose !== "access") {
      return res.redirect("http://localhost:3000/login?message=Invalid+or+missing+token.+Please+login+again.");
    }
    req.user = decoded;
    console.log("this is from authenticate req.user");
    console.log(req.user);
    next();
  } catch (err) {
    return res.redirect("http://localhost:3000/login?message=Invalid+or+missing+token.+Please+login+again.");
  }
};

const authenticateLogin = (req, res, next) => {
  const token = req.cookies.authToken;
  if (token) {
    try {
      const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
      if (decoded.purpose === "access") {
        return res.redirect("http://localhost:3000/outgoingRequests");
      }
      req.user = decoded;
      console.log("this is from authenticate login");
      console.log(req.user);
      next();
    } catch (err) {
      // res.status(500).json({ message: "User not verified successfully", status: 500, error: err });
      console.log(req.user);
      next();
    }
  } else {
    next();
  }
};

const authenticateRegistration = (req, res, next) => {
  const token = req.cookies.authToken;
  // console.log("this is the cookie that the authenticateRegistration receives.", token);
  if (!token) {
    return res.redirect(
      "http://localhost:3000/login?message=Registration+failed+due+to+missing+or+invalid+token.+Please+try+again."
    );
  }

  try {
    const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
    console.log("this is from authenticateRegistration");
    console.log(decoded);
    if (decoded.purpose !== "signup") {
      return res.redirect(
        "http://localhost:3000/login?message=Registration+failed+due+to+missing+or+invalid+token.+Please+try+again."
      );
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect(
      "http://localhost:3000/login?message=Registration+failed+due+to+missing+or+invalid+token.+Please+try+again."
    );
  }
};

const authenticatePassReset = (req, res, next) => {
  const token = req.cookies.authToken;
  // console.log("this is the cookie that the authenticateRegistration receives.", token);
  if (!token) {
    return res.redirect(
      "http://localhost:3000/login?message=Password+reset+failed+due+to+missing+or+invalid+token.+Please+try+again."
    );
  }

  try {
    const decoded = jwt.verify(token, "ramya-preethinthran-sharun");
    console.log("this is from authenticate password reset");
    console.log(decoded);
    if (decoded.purpose !== "password_reset") {
      return res.redirect(
        "http://localhost:3000/login?message=Password+change+failed+due+to+wrong+purpose+of+token.+Please+try+again."
      );
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect(
      "http://localhost:3000/login?message=Registration+failed+due+to+missing+or+invalid+token.+Please+try+again."
    );
  }
};

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", authenticateLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/dashboard-data", authenticate, async (req, res) => {
  try {
    const userdeets = await User.find({ rollno: req.user.rollno });
    console.log(userdeets);
    res.json(userdeets);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch user details", status: 500 });
  }
});

app.get("/register", authenticateRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.get("/password_reset", authenticatePassReset, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "password_reset.html"));
});

app.get("/register-data", authenticateRegistration, (req, res) => {
  console.log(req.user);
  const email = req.user.email;
  console.log("this is to check if name is working in register-data get route", name);
  const name = req.user.name;
  console.log("this is to check if name is working in register-data get route", name);
  const rollno = email.split("@")[0].toUpperCase();
  res.json({ name, email, rollno });
});

app.get("/password-change-deets", authenticatePassReset, (req, res) => {
  // console.log(req.user);
  const email = req.user.email;
  // console.log("this is to check if name is working in register-data get route", name);
  const name = req.user.name;
  // console.log("this is to check if name is working in register-data get route", name);
  const rollno = email.split("@")[0].toUpperCase();
  res.json({ name, email, rollno });
});

app.get("/newRequest", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "addrequest.html"));
});

app.get("/listSkills", async (req, res) => {
  try {
    const skills = await Skill.find({});
    res.json(skills);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch skills", status: 500 });
  }
});

app.get("/missingSkills", authenticate, async (req, res) => {
  try {
    const rollno = req.user.rollno;
    const skills = await User.aggregate([
      {
        $match: {
          rollno: rollno,
        },
      },
      {
        $project: {
          skills: 1,
          _id: 0,
        },
      },
      {
        $lookup: {
          from: "skills",
          localField: "skills",
          foreignField: "_id",
          as: "result",
        },
      },
    ]);
    const missingSkills = await Skill.find({
      _id: { $nin: skills[0].skills },
    });
    res.json(missingSkills);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch missing skills", status: 500 });
  }
});

app.get("/userSkills", authenticate, async (req, res) => {
  try {
    const rollno = req.user.rollno;
    const skills = await User.aggregate([
      {
        $match: {
          rollno: rollno,
        },
      },
      {
        $unwind: {
          path: "$skills",
        },
      },
      {
        $lookup: {
          from: "skills",
          localField: "skills",
          foreignField: "_id",
          as: "name",
        },
      },
      {
        $unwind: {
          path: "$name",
        },
      },
      {
        $project: {
          _id: 0,
          name: ["$name.skill", "$name._id"],
        },
      },
    ]);
    res.json(skills);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch skills for this user", status: 500 });
  }
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/password_reset", passport.authenticate("google-password-reset", { scope: ["profile", "email"] }));

//below is the google redirect route but stupid prettier wont show name when collapsed
app.get(
  "/auth/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login?message=Authentication+failed.Please+try+again.",
    failureMessage: true,
  }),
  (req, res) => {
    if (req.user) {
      // console.log("req.user is there and working", req.user);
      res.cookie("authToken", req.user, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 600000, // 10 minutes
      });
      res.redirect("/register");
    }
  }
);

//below is the google redirect route for password reseting
app.get(
  "/auth/password-reset-callback",
  passport.authenticate("google-password-reset", {
    session: false,
    failureRedirect:
      "/login?message=Attempt+to+reset+password+failed.Please+make+sure+you+are+using+PSG+tech+email+and+you+account+exits+and+try+again.",
    failureMessage: true,
  }),
  (req, res) => {
    if (req.user) {
      // console.log("req.user is there and working", req.user);
      res.cookie("authToken", req.user, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 600000, // 10 minutes
      });
      res.redirect("/password_reset");
    }
  }
);

app.post("/register", authenticateRegistration, async (req, res) => {
  const { password, phone } = req.body;
  console.log(password);
  const email = req.user.email;
  const rollno = email.split("@")[0].toUpperCase();
  const name = req.user.name;

  // // let email = `${rollno}@psgtech.ac.in`;
  // let email = "ramyaraja1206@gmail.com";
  // const hashedPassword = await bcrypt.hash(password, 10);

  // const token = crypto.randomBytes(16).toString("hex");
  // pendingUsers[token] = { email, rollno, name, hashedPassword, createdAt: Date.now() };

  // const verificationLink = `http://localhost:3000/verify-email?token=${token}`;

  // console.log(`Verification email sent to ${email} with link: ${verificationLink}`);

  // res.status(200).json({ message: "Check your email to verify your account." });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ rollno: rollno, name: name, password: hashedPassword, phone: phone });
    await newUser.save();
    res.status(200).json({ message: "User registered successfully", status: 200 });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({ message: "Error registering user", status: 500 });
  }
});

app.post("/password_reset", authenticatePassReset, async (req, res) => {
  const { password } = req.body;
  console.log(password);
  const email = req.user.email;
  const rollno = email.split("@")[0].toUpperCase();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const updatedUser = await User.findOneAndUpdate(
      { rollno: rollno }, // Find user with this rollno
      { password: hashedPassword }, // Update the password field
      { new: true } // Return the updated user document
    );
    if (updatedUser) {
      console.log("Password updated successfully for user:", rollno);
    } else {
      console.error("User not found with rollno:", rollno);
    }
    res.status(200).json({ message: "Password Change successfull", status: 200 });
  } catch (error) {
    console.error("Password change error1: ", error);
    res.status(500).json({ message: "Password change error 2", status: 500 });
  }
});

app.get("/verify-email", async (req, res) => {
  const { token } = req.query; // Extract token from the URL query

  const userData = pendingUsers[token];
  if (!userData) {
    return res.status(400).json({ message: "Invalid or expired token." });
  }

  const tokenExpiration = 60 * 60 * 1000; // 1 hour in milliseconds
  if (Date.now() - userData.createdAt > tokenExpiration) {
    delete pendingUsers[token]; // Cleanup expired data
    return res.status(400).json({ message: "Token has expired." });
  }

  try {
    const newUser = new User({
      rollno: userData.rollno,
      name: userData.name,
      password: userData.hashedPassword,
    });
    console.log(newUser);
    await newUser.save();

    // Remove user from pendingUsers
    delete pendingUsers[token];

    // res.status(200).json({ message: 'Email verified successfully! Your account is now active.' });
    res.send(`
      <script>
        localStorage.setItem('registrationStatus', 'verified');
        window.close();
      </script>
    `);
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).json({ message: "Error verifying email." });
  }
});

app.post("/login", async (req, res) => {
  console.log(req.body);
  const { rollno, password, remember_me } = req.body;
  try {
    const user = await User.findOne({ rollno: rollno });

    if (user && (await bcrypt.compare(password, user.password))) {
      const tokenExpiry = remember_me ? "7d" : "15m";
      const token = generateToken(rollno, tokenExpiry);
      console.log("This is to check the cookie", token); //vulnerabiity do not keep this in the final code if kept ramya's responsibility.
      res.cookie("authToken", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: remember_me ? 7 * 24 * 60 * 60 * 1000 : null,
      });

      res.status(200).json({ message: "User credentials authenticated", status: 200 });
    } else {
      res.status(401).json({ message: "Bad credentials", status: 401 });
    }
  } catch (error) {
    console.error("Error during login: ", error);
    res.status(500).send("Error logging in");
  }
});

app.post("/logout", (req, res) => {
  try {
    res.clearCookie("authToken", {
      httpOnly: true,
      sameSite: "strict",
      secure: true,
    });
    res.sendStatus(200);
  } catch (error) {
    console.error("Error clearing cookie:", error);
    res.status(500).send({ error: "Failed to logout" });
  }
});

app.post("/addUserSkill", authenticate, async (req, res) => {
  const { skillid } = req.body;
  const userid = req.user.rollno;
  console.log(skillid);
  try {
    const newUserSkill = await User.findOneAndUpdate({ rollno: userid }, { $addToSet: { skills: skillid } }, { new: true });
    console.log(newUserSkill);
    res.status(200).json(newUserSkill);
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ message: "Error updating skills", error: error.message });
  }
});

app.post("/removeUserSkill", authenticate, async (req, res) => {
  const { skillid } = req.body;
  const userid = req.user.rollno;
  console.log(skillid);
  try {
    const removeUserSkill = await User.findOneAndUpdate({ rollno: userid }, { $pull: { skills: skillid } }, { new: true });
    console.log(removeUserSkill);
    res.status(200).json(removeUserSkill);
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ message: "Error updating skills", error: error.message });
  }
});

app.post("/displayPhone", authenticate, async (req, res) => {
  const { display } = req.body;
  const userid = req.user.rollno;
  console.log(display);
  try {
    const toggle = await User.findOneAndUpdate({ rollno: userid }, { $set: { phoneVisible: display } }, { new: true });
    // console.log(toggle);
    res.status(200).json(toggle);
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ message: "Error updating skills", error: error.message });
  }
});

app.post("/addSkill", async (req, res) => {
  const { skill } = req.body;
  console.log(req.body);
  console.log(skill);
  console.log(req.body.skill);

  try {
    const nextId = await getNextSequence("skills");
    const newSubject = new Skill({ _id: nextId, skill: skill });
    await newSubject.save();
    res.status(201).json({ message: "Subject registered successfully", status: 201 });
  } catch (error) {
    console.error("Error registering Subject: ", error);
    await Counter.findOneAndUpdate(
      { id: "skills" },
      { $inc: { seq: -1 } } // Decrement the counter
    );
    res.status(500).json({ message: "Error registering Subject", status: 500 });
  }
});

app.post("/newRequest", authenticate, async (req, res) => {
  const { subjectId, title, description } = req.body;
  const senderId = req.user.rollno;
  console.log(req.body);
  console.log(senderId, subjectId, title, description);

  try {
    const newRequest = new Request({
      senderId: senderId,
      subjectId: subjectId,
      title: title,
      description: description,
    });
    await newRequest.save();
    res.status(201).json({ message: "Request sent successfully", status: 201 });
  } catch (error) {
    console.error("Error creating request ", error);
    res.status(500).json({ message: "Error creating request", status: 500 });
  }
});

app.get("/outgoingRequests", authenticate, (req, res) => {
  res.sendFile(__dirname + "/public/outgoingRequests.html");
});

app.get("/api/outgoingRequests", authenticate, async (req, res) => {
  const requesterId = req.user.rollno;
  try {
    const myReqs = await User.aggregate([
      {
        $lookup: {
          from: "requests",
          localField: "rollno",
          foreignField: "senderId",
          as: "req",
        },
      },
      {
        $unwind: {
          path: "$req",
        },
      },
      {
        $match: {
          rollno: requesterId,
        },
      },
      {
        $addFields: {
          subjId: "$req.subjectId",
          title: "$req.title",
          descr: "$req.description",
          status: "$req.status",
          requestId: "$req._id",
          phoneVisible: "$req.phoneVisible",
        },
      },
      {
        $lookup: {
          from: "skills",
          localField: "subjId",
          foreignField: "_id",
          as: "sk",
        },
      },
      {
        $addFields: {
          subjName: { $arrayElemAt: ["$sk", 0] },
        },
      },
      {
        $addFields: {
          subjName: "$subjName.skill",
        },
      },
      {
        $unset: ["req", "sk", "password", "__v", "subjId", "phone", "skills"],
      },
    ]);
    res.json(myReqs);
    // res.render('outgoingRequests', {
    //   requests: myReqs });
    // console.log(myReqs);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch outgoing requests", status: 500 });
  }
});

app.delete("/api/outgoingRequests/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedRequest = await Request.findByIdAndDelete(id);
    if (deletedRequest) {
      res.status(200).json({ message: "Request deleted successfully", status: 200 });
    } else {
      res.status(404).json({ message: "Request not found", status: 404 });
    }
  } catch (error) {
    console.error("Error deleting request:", error);
    res.status(500).json({ message: "Failed to delete request", status: 500 });
  }
});

app.get("/incomingRequests", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public/tutoringRequests.html"));
});

app.get("/api/incomingRequests", authenticate, async (req, res) => {
  const receiverId = req.user.rollno;
  const requestStatus = req.query.status || "Pending";
  console.log(requestStatus);

  console.log(receiverId);
  try {
    const myReqs = await User.aggregate([
      {
        $match: {
          rollno: receiverId,
        },
      },
      {
        $unwind: {
          path: "$skills",
        },
      },
      {
        $lookup: {
          from: "skills",
          localField: "skills",
          foreignField: "_id",
          as: "sk",
        },
      },
      {
        $addFields: {
          skillName: { $arrayElemAt: ["$sk", 0] },
        },
      },
      {
        $addFields: {
          skillName: "$skillName.skill",
        },
      },
      {
        $addFields: {
          skillId: "$skills",
        },
      },
      {
        $unset: ["__v", "sk", "_id", "password", "skills"],
      },
      {
        $lookup: {
          from: "requests",
          localField: "skillId",
          foreignField: "subjectId",
          as: "matchingReq",
        },
      },
      {
        $unwind: {
          path: "$matchingReq",
        },
      },
      //   {
      //     $addFields: {
      //       matchingReq: {$arrayElemAt: ["$matchingReq", 0]}
      //     }
      //   },
      {
        $addFields: {
          reqId: "$matchingReq._id",
          senderId: "$matchingReq.senderId",
          title: "$matchingReq.title",
          descr: "$matchingReq.description",
          status: "$matchingReq.status",
          rejectedBy: "$matchingReq.rejectedBy",
          phoneVisible: "$matchingReq.phoneVisible",
          timestamp: {
            $dateToString: {
              format: "%Y-%m-%d",
              date: { $toDate: "$matchingReq._id" },
            },
          },
        },
      },
      {
        $match: {
          status: requestStatus,
        },
      },
      {
        $unwind: {
          path: "$rejectedBy",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $unset: "matchingReq",
      },
      {
        $match: {
          $expr: {
            $and: [{ $ne: ["$rollno", "$senderId"] }, { $ne: ["$rollno", "$rejectedBy"] }],
          },
        },
      },

      {
        $lookup: {
          from: "users",
          localField: "senderId",
          foreignField: "rollno",
          as: "senderName",
        },
      },

      {
        $addFields: {
          senderName: { $arrayElemAt: ["$senderName", 0] },
        },
      },
      {
        $addFields: {
          senderName: "$senderName.name",
          senderPhone: {
            $cond: {
              if: { $eq: ["$phoneVisible", true] },
              then: "$senderName.phone",
              else: null,
            },
          },
        },
      },
      {
        $unset: ["SenderName", "__v", "password"],
      },
    ]);
    console.log(myReqs);
    res.json(myReqs);
    console.log(myReqs);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch incoming requests", status: 500 });
  }
});

app.post("/api/request/:reqId/accept", authenticate, async (req, res) => {
  console.log("accepting");
  const { reqId } = req.params;
  console.log(req.user);
  try {
    const request = await Request.findById(reqId);
    console.log(request);
    if (request) {
      request.status = "Accepted";
      request.tutorId = req.user.rollno;

      await request.save();
      res.status(200).send({ message: "Request accepted" });
    } else {
      res.status(404).send({ error: "Request not found" });
    }
  } catch (error) {
    res.status(500).send({ error: "Internal Sever Error" });
  }
});

app.post("/api/request/reject", authenticate, async (req, res) => {
  console.log("testtesttest");
  const { reqId } = req.body;
  console.log(reqId);
  try {
    const request = await Request.findById(reqId);
    console.log(request);
    if (request) {
      console.log("right before push into rejectedBy array");
      console.log(request.rejectedBy);
      // const result = await Request.updateOne(
      //   { _id: reqId },
      //   { $addToSet: { rejectedBy: req.user.rollno } }
      // );
      // request.rejectedBy = [...request.rejectedBy, req.user.rollno];
      try {
        request.rejectedBy.addToSet(req.user.rollno);
        await request.save();
      } catch (err) {
        console.error("Error updating request:", err);
      }
      res.status(200).send({ message: "Request rejected" });
    } else {
      res.status(404).send({ error: "Request not found" });
    }
  } catch (error) {
    res.status(500).send({ error: "Internal Sever Error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
