
///////////////////////////////////////////////////
///CONF JSON
const conf  = require("./conf.json")
const mysql = require('mysql')

const con = mysql.createConnection({
  host: conf.host,
  user: conf.user,
  password: conf.password,
  database: conf.database,
  port: conf.port
})


con.connect((err)=>{
  if(err){return console.log("[ERROR]\t mysql connection " + err)}
  console.log("[INFO]\t mysql connection OK")
})


exports.con = con
///////////////////////////////////////////////////



