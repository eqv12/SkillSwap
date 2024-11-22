// utils.js
import Counter from '../models/Counter.js'; // Import the Counter model

// Helper function to get the next sequence ID
export async function getNextSequence(name) {
  const counter = await Counter.findOneAndUpdate(
    { id: name },
    { $inc: { seq: 1 } }, // Increment the sequence by 1
    { new: true, upsert: true } // Create the document if it doesn't exist
  );
  return counter.seq;
}
