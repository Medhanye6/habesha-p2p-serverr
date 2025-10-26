import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'

// Define the structure of our database
type Data = {
  users: any[] // We'll store users in an array
  merchants: any[]
  ads: any[] // Add this line
  trades: any[]
}

// Set up the database
const defaultData: Data = { users: [], merchants: [], ads: [], trades: [] } // Add trades here
const adapter = new JSONFile<Data>('db.json')
const db = new Low<Data>(adapter, defaultData)

// A function to initialize the database
export async function setupDb() {
  // Read data from JSON file, setting default data if file doesn't exist
  await db.read()
  // You must call db.write() to save the default data to the file
  await db.write()
}

// Export the database instance to be used in other files
export default db
