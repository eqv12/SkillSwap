import { connect } from "mongoose";

const dbURI =
  "mongodb+srv://ramya:Wimmss123.@dev-skill-swap-cluster.efbjn.mongodb.net/skillSwap?retryWrites=true&w=majority&appName=dev-skill-swap-cluster";

// Function to establish the database connection
const connectDB = async () => {
  try {
    await connect(dbURI);
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error", err);
    process.exit(1); // Exit the process with failure
  }
};

// Export the connectDB function
export default connectDB;

