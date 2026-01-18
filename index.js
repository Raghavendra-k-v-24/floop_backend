import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import bodyParser from "body-parser";

import { authenticate } from "./middleware/auth.js";

import {
  User,
  Portfolio,
  Review,
  Pin,
  Comment,
  Event,
} from "./database/index.js";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: ["https://www.floop.design", "http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(bodyParser.json());

app.post("/api/signup", async (req, res) => {
  try {
    const data = req.body;
    const { name, email, password } = data;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(201)
      .json({ message: "User created successfully", token });
  } catch (err) {
    console.error("Signing up user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const data = req.body;
    const { email, password } = data;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(201)
      .json({ message: "User created successfully", token });
  } catch (err) {
    console.error("Logging in user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/api/user", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { name, password, role } = data;
    const updateQuery = {};
    const setFields = {};
    const addToSetFields = {};

    // normal fields → $set
    if (name) setFields.name = name;

    if (password) {
      setFields.password = await bcrypt.hash(password, 10);
    }

    // array append fields → $addToSet
    if (role) {
      addToSetFields.role = role;
    }

    // attach operators only if needed
    if (Object.keys(setFields).length > 0) {
      updateQuery.$set = setFields;
    }

    if (Object.keys(addToSetFields).length > 0) {
      updateQuery.$addToSet = addToSetFields;
    }

    if (Object.keys(updateQuery).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    await User.findByIdAndUpdate(req.userId, updateQuery, { new: true });

    return res.status(200).json({ message: "User updated successfully" });
  } catch (err) {
    console.error("Update user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/portfolio", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { portfolioLink, intent } = data;

    const ownerUserId = intent === "reviewee" ? req.userId : null;
    const createdByUserId = req.userId;

    if (!portfolioLink) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const portfolio = new Portfolio({
      ownerUserId,
      createdByUserId,
      portfolioLink,
    });
    await portfolio.save();

    return res
      .status(201)
      .json({ message: "Portfolio created successfully", portfolio });
  } catch (err) {
    console.error("Portfolio creation error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/review", authenticate, async (req, res) => {
  try {
    const { portfolioId, reviewerEmail, revieweeEmail, intent } = req.body;

    const userId = req.userId;

    if (!portfolioId) {
      return res.status(400).json({ message: "portfolioId is required" });
    }

    if (!["reviewee", "reviewer"].includes(intent)) {
      return res.status(400).json({ message: "Invalid intent" });
    }

    const user = await User.findById(userId);

    // 🔐 Validate intent against capability
    if (!user.role.includes(intent)) {
      return res.status(403).json({
        message: `User cannot create review as ${intent}`,
      });
    }

    let revieweeId = null;
    let reviewerId = null;
    let invitedReviewerEmail = null;

    if (intent === "reviewee") {
      revieweeId = userId;

      if (reviewerEmail) {
        const reviewer = await User.findOne(
          { email: reviewerEmail },
          { _id: 1 },
        );
        reviewerId = reviewer?._id || null;
        invitedReviewerEmail = reviewerEmail;
      }
    }

    if (intent === "reviewer") {
      reviewerId = userId;

      if (revieweeEmail) {
        const reviewee = await User.findOne(
          { email: revieweeEmail },
          { _id: 1 },
        );
        revieweeId = reviewee?._id || null;
      }
    }

    const review = await Review.create({
      portfolioId,
      createdByUserId: userId,
      intent,
      revieweeId,
      reviewerId,
      invitedReviewerEmail,
      accessToken: crypto.randomBytes(24).toString("hex"),
    });

    return res.status(201).json({
      message: "Review created successfully",
      review,
    });
  } catch (err) {
    console.error("Review creation error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/api/review", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { reviewId, goals, accessType } = data;
    const revieweeId = req.userId;

    if (!reviewId) {
      return res.status(400).json({ message: "reviewId is required" });
    }

    const updateQuery = {};
    const setFields = {};
    // const addToSetFields = {};

    // normal fields → $set
    if (accessType) setFields.accessType = accessType;

    if (Array.isArray(goals) && goals.length > 0) {
      setFields.goals = goals;
    }

    // attach operators only if needed
    if (Object.keys(setFields).length > 0) {
      updateQuery.$set = setFields;
    }

    // if (Object.keys(addToSetFields).length > 0) {
    //   updateQuery.$addToSet = addToSetFields;
    // }

    if (Object.keys(updateQuery).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    const updatedReview = await Review.findOneAndUpdate(
      { _id: reviewId, revieweeId }, // only owner can update
      updateQuery,
      { new: true },
    );

    if (!updatedReview) {
      return res
        .status(404)
        .json({ message: "Review not found or unauthorized" });
    }

    return res.status(200).json({ message: "Review updated successfully" });
  } catch (err) {
    console.error("Review update error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(3000, () => {
  console.log("Server is running at port 3000");
});
