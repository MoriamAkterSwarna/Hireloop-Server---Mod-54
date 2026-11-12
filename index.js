import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose-cjs";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "dummy_secret_key");

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

const mongoUri =
  process.env.MONGO_DB_URI ||
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.vyznij5.mongodb.net/`;

const client = new MongoClient(mongoUri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("hireloopdb");
const users = database.collection("user");
const jobs = database.collection("jobs");
const applications = database.collection("applications");
const payments = database.collection("payments");
const companies = database.collection("companies");

// JWKS for verifying tokens issued by Better Auth (Module 54-3)
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const JWKS = createRemoteJWKSet(
  new URL(`${CLIENT_URL}/api/auth/jwks`),
);

// 54-3: verifyToken middleware
const verifyToken = async (req, res, next) => {
  const header = req?.headers;
  console.log("Authorization Header:", header?.authorization);
  if (!header?.authorization) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized",
    });
  }
  const token = header.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized",
    });
  }
  // verify token using JWKS
  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch (error) {
    console.log("JWT Verification Error:", error?.message || error);
    return res.status(403).json({ message: "Forbidden" });
  }
};

// 54-4: verify seeker middleware
const verifySeeker = async (req, res, next) => {
  const email = req.user?.email;
  if (!email) {
    return res.status(403).send({ message: "Forbidden access" });
  }
  const query = { email: email };
  const user = await users.findOne(query);
  if (user?.role !== "seeker") {
    return res.status(403).send({ message: "Forbidden access" });
  }
  next();
};

// 54-5: verify recruiter middleware
const verifyRecruiter = async (req, res, next) => {
  const email = req.user?.email;
  if (!email) {
    return res.status(403).send({ message: "Forbidden access" });
  }
  const query = { email: email };
  const user = await users.findOne(query);
  if (user?.role !== "recruiter") {
    return res.status(403).send({ message: "Forbidden access" });
  }
  next();
};

// 54-6: verify admin middleware
const verifyAdmin = async (req, res, next) => {
  const email = req.user?.email;
  if (!email) {
    return res.status(403).send({ message: "Forbidden access" });
  }
  const query = { email: email };
  const user = await users.findOne(query);
  if (user?.role !== "admin") {
    return res.status(403).send({ message: "Forbidden access" });
  }
  next();
};

app.get("/", (req, res) => {
  res.send("hire loop is looping");
});

// ==========================================
// User & Admin Related APIs (54-6)
// ==========================================

// 54-6: Admin only endpoint to list all users
app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  const cursor = users.find({});
  const result = await cursor.toArray();
  res.send(result);
});

// Admin stats summary
app.get("/api/admin/stats", verifyToken, verifyAdmin, async (req, res) => {
  const totalUsers = await users.countDocuments({});
  const seekers = await users.countDocuments({ role: "seeker" });
  const recruiters = await users.countDocuments({ role: "recruiter" });
  const admins = await users.countDocuments({ role: "admin" });
  const totalJobs = await jobs.countDocuments({});
  const totalApplications = await applications.countDocuments({});
  const totalPayments = await payments.countDocuments({ status: "complete" });

  res.send({
    totalUsers,
    seekers,
    recruiters,
    admins,
    totalJobs,
    totalApplications,
    totalPayments,
  });
});

// Admin endpoint to update a user's role
app.patch("/api/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!["seeker", "recruiter", "admin"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }
  const filter = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: { role, updatedAt: new Date() },
  };
  const result = await users.updateOne(filter, updateDoc);
  res.send({ success: true, result });
});

app.get("/api/users/:id/premium", async (req, res) => {
  const id = req.params.id;
  const query = { _id: new ObjectId(id) };
  const result = await users.findOne(query, { projection: { premium: 1 } });
  res.send(result);
});

// ==========================================
// Profile Related APIs (54-7 & 54-8)
// ==========================================

// Get authenticated user profile
app.get("/api/profile", verifyToken, async (req, res) => {
  const email = req.user?.email;
  const user = await users.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  res.send(user);
});

// 54-8: Update Profile PATCH API
app.patch("/api/profile", verifyToken, async (req, res) => {
  const email = req.user?.email;
  if (!email) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const updateData = req.body;
  const filter = { email };
  const updateDoc = {
    $set: {
      ...(updateData.name && { name: updateData.name }),
      ...(updateData.image && { image: updateData.image }),
      ...(updateData.title && { title: updateData.title }),
      ...(updateData.phone && { phone: updateData.phone }),
      ...(updateData.location && { location: updateData.location }),
      ...(updateData.bio && { bio: updateData.bio }),
      ...(updateData.company && { company: updateData.company }),
      ...(updateData.website && { website: updateData.website }),
      updatedAt: new Date(),
    },
  };
  const result = await users.updateOne(filter, updateDoc);
  res.json({ success: true, result });
});


// ==========================================
// Jobs Related APIs (54-5)
// ==========================================

// Publicly readable jobs
app.get("/api/jobs", async (req, res) => {
  const query = {};
  if (req.query) {
    if (req.query.jobType) {
      query.jobType = req.query.jobType;
    }
    if (req.query.isRemote) {
      query.isRemote = req.query.isRemote === "true";
    }
    if (req.query.category) {
      query.category = req.query.category;
    }
    if (req.query.search) {
      query.$or = [
        { title: { $regex: req.query.search, $options: "i" } },
        { company: { $regex: req.query.search, $options: "i" } },
        { responsibilities: { $regex: req.query.search, $options: "i" } },
        { requirements: { $regex: req.query.search, $options: "i" } },
      ];
    }
  }

  const cursor = jobs.find(query);
  const result = await cursor.toArray();
  res.send(result);
});

app.get(`/api/jobs/:id`, async (req, res) => {
  const id = req.params.id;
  const query = { _id: new ObjectId(id) };
  const result = await jobs.findOne(query);
  res.send(result);
});

// 54-5: Recruiter protected route to create job
app.post("/api/jobs", verifyToken, verifyRecruiter, async (req, res) => {
  const job = req.body;
  const result = await jobs.insertOne(job);
  res.send(result);
});

// 54-5: Recruiter protected route to delete job
app.delete("/api/jobs/:id", verifyToken, verifyRecruiter, async (req, res) => {
  const id = req.params.id;
  const query = { _id: new ObjectId(id) };
  const result = await jobs.deleteOne(query);
  res.send(result);
});

// ==========================================
// Applications Related APIs (54-4)
// ==========================================

// 54-4: Seeker protected route to get applications
app.get(
  "/api/applications",
  verifyToken,
  verifySeeker,
  async (req, res) => {
    const query = {};
    if (req.query.applicantId) {
      query.userId = req.query.applicantId;
    }
    const cursor = applications.find(query);
    const result = await cursor.toArray();
    res.send(result);
  }
);

// 54-4: Seeker protected route to get count
app.get(
  "/api/applications/count",
  verifyToken,
  verifySeeker,
  async (req, res) => {
    const query = {};
    if (req.query.applicantId) {
      query.userId = req.query.applicantId;
    }
    const result = await applications.countDocuments(query);
    res.send({ count: result });
  }
);

// 54-4: Seeker protected route to submit application
app.post(
  "/api/applications",
  verifyToken,
  verifySeeker,
  async (req, res) => {
    const application = req.body;
    const result = await applications.insertOne(application);
    res.send(result);
  }
);

// ==========================================
// Payments Related APIs
// ==========================================
app.post("/api/payments/checkout-verify", async (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.send({ success: false, message: "Session ID is required" });
  }

  const { status, payment_status, customer_email, metadata, payment_intent } =
    await stripe.checkout.sessions.retrieve(sessionId);

  if (status === "complete" && payment_status === "paid") {
    const sessionQuery = { sessionId };
    const existingPayment = await payments.findOne(sessionQuery);
    if (existingPayment) {
      return res.send({ success: false, message: "Payment already verified" });
    }
    const payment = {
      sessionId,
      status,
      payment_status,
      customer_email,
      userId: metadata?.userId,
      payment_date: new Date(),
      payment_intent,
    };

    const result = await payments.insertOne(payment);

    // update the user table
    if (metadata?.userId) {
      const query = { _id: new ObjectId(metadata.userId) };
      const updatedDoc = {
        $set: {
          premium: true,
        },
      };
      const updateResult = await users.updateOne(query, updatedDoc);
      res.send({ success: true, result, updateResult });
      return;
    }
    res.send({ success: true, result });
    return;
  }
  res.send({ success: false, message: "Payment verification failed" });
});

app.listen(port, () => {
  console.log(`hire loop is running on port ${port}`);
});

export default app;
