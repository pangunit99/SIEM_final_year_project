var express = require('express');
var router = express.Router();
const bodyParser = require('body-parser')
const moment = require('moment')
const fs = require('fs');
const logParser = require('@slaughtr/apache-log-parser');
var nodemailer = require('nodemailer');

const SQL_INJECTION_REGEX = /(\b(UNION|SELECT|UPDATE|DELETE|INSERT|WHERE|ORDER BY|GROUP BY|DELAY|SLEEP|BENCHMARK|OR|AND|DELAY|DROP)\b|\b(?:--|\/\*)\s)/i;
const ERROR_INJECTION = /(\b(ORDER|BY|GROUP|AND)\b|\b(?:--|\/\*)\s)/i;
const UNION_INJECTION = /(\b(UNION|SELECT|INSERT|ALERT|DROP|;)\b)/i;
const Time_based = /(\b(SLEEP|BENCHMARK|DELAY)\b)/i;
const BOOLEAN_based = /\b((ASCII|LENGTH|OR))\b/i;
let getDate = [];
let gettabledata = [];
let countipcollect = [];
let logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
var oldinj = 0;
var nowinj = 0;

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'railpang1999@gmail.com',
    pass: 'tygjmjrjwjrqpbcr'
  }
});

var mailOptions = {
  from: 'railpang1999@gmail.com',
  to: 'pangrail19@gmail.com',
  subject: 'Important!!! You Have a new SQL injection !!!!!',
  text: 'Important!!! You Have a new SQL injection !!!!! Please check detail in SIEM system!'
};

function analyzeLogFile(logFilePath) {
  //array to null
  getDate = [];
  gettabledata = [];
  countipcollect = [];

//loop for lof to check injection
  const logEntries = fs.readFileSync(logFilePath, 'utf-8').split('\n');
  const results = {
    totalRequests: 0,
    totrequest:[],

    sqlInjectionAttempts: 0,
    sql_injectionarray:[],

    errorInjection :0,
    error_injectionarray:[],

    unionInjection :0,
    union_injectionarray:[],

    timebasedInjection:0,
    timebased_injectionarray:[],

    booleanInjection:0,
    boolean_Injectionarray:[],

    privilegeInjection:0,
    privilege_injectionarray:[],
  };
  //const printontable = [];


  logEntries.forEach((entry) => {
    if (entry) {
      results.totalRequests++;
      if (SQL_INJECTION_REGEX.test(entry)) {
        results.sqlInjectionAttempts++;
        results.sql_injectionarray.push(logParser({ string: entry })) 

        if(BOOLEAN_based.test(entry)){
            results.booleanInjection++;
            results.boolean_Injectionarray.push(logParser({ string: entry }));
  
        }else if(Time_based.test(entry)){
            results.timebasedInjection++;
            results.timebased_injectionarray.push(logParser({ string: entry }));
  
        }else if(ERROR_INJECTION.test(entry)){
          results.errorInjection++;
          results.error_injectionarray.push(logParser({ string: entry }));

        }else  if(UNION_INJECTION.test(entry)){
          results.unionInjection++;
          results.union_injectionarray.push(logParser({ string: entry }));

        }
      }else{
        results.totrequest.push(logParser({ string: entry }))
      }
    }
  });




  // format the date
  console.log(results.sql_injectionarray);
  const a  =results.sql_injectionarray;
  let text = '';
  let text2 = '';
  for (let i =0 ;i< a.length ;i++){
      let last=a.length-1
      text2 = a[i].time;
      text = a[last-i].time;
      //get date

      let chartformat = new Date(text2.split(':')[0]);
      let chartdate = moment(chartformat).format('DD-MM-YYYY');
      //chart2 use
      getDate.push({"date":chartdate});


      //table array1 time
      if(gettabledata.length<10){
        let type ;
        if(BOOLEAN_based.test(a[last-i].resource)|BOOLEAN_based.test(a[last-i].referer)){
          type="Boolean injection"

        }else if(Time_based.test(a[last-i].resource)|Time_based.test(a[last-i].referer)){
          type="Time based injection"

        }else if(ERROR_INJECTION.test(a[last-i].resource)|ERROR_INJECTION.test(a[last-i].referer)){
          type="Error injection"

        }else  if(UNION_INJECTION.test(a[last-i].resource)|UNION_INJECTION.test(a[last-i].referer)){
          type="UNION injection"

        }else{
          type="injection"
        }
        let normal = text.split(':')[0]+" "+text.split(':')[1]+":"+text.split(':')[2];
        gettabledata.push({"time":normal,"itype":type});
    }


  }



  //countipcollect
  for(let countcollect = 0 ; countcollect<results.totrequest.length;countcollect++){
    let ip=results.totrequest[countcollect].ip

    //all view ip array
    countipcollect.push({"date":ip});

  }


  return results;
}




//error log
function errorlog(log){
  const err={
    count:0,
    elog:[]
  }

  const errlog = fs.readFileSync(log, 'utf-8').split('\n');
  errlog.forEach((entry) => {
    err.count++;
    err.elog.push(entry)
  }
  )
  return err;
}





// group injection date(dd-mm-yyyy) and number and save on array
function setter(data){
  let groupdate=[]
  data.forEach((item,i)=>{
    let index = -1
    let isExists = groupdate.some((newItem,j)=>{
      if(item.date==newItem.date){
        index=j;
        return true;
      }
    })
    if(!isExists){
      groupdate.push({
        date: item.date,
        sublist:[item]
      })
    }else{
      groupdate[index].sublist.push(item);
    }

  })
  console.log(groupdate)
  const testformat=[]
  for(let count =0 ;count<groupdate.length;count++){
    testformat.push([groupdate[count].date,groupdate[count].sublist.length])
  }
  console.log(testformat)
  return groupdate;
}




router.get('/', function(req, res, next) {
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  //get log information
  const linechart = setter(getDate);

  //pic2
  const date=[]
  const number=[]
  for(let count =0 ;count<linechart.length;count++){
    date.push("'"+linechart[count].date+"'")
    number.push(linechart[count].sublist.length)
  }


  //table2
  const ipnumber=[]
  const cal = setter(countipcollect);
  for(let count =0 ;count<cal.length;count++){
    ipnumber.push({"ip":cal[count].date,"times":cal[count].sublist.length})
  }

  // Sort the number by more to lower
  function GetSortOrder(prop) {    
    return function(a, b) {    
        if (a[prop] < b[prop]) {    
            return 1;    
        } else if (a[prop] > b[prop]) {    
            return -1;    
        }    
        return 0;    
    }    
  }
  ipnumber.sort(GetSortOrder("times"));
  while (ipnumber.length>8){
    ipnumber.pop();
  }


  const syserror = errorlog('C:/xampp/apache/logs/error.log');

  console.log('test')
  console.log(date)
  //const data = [logFileResults.totalRequests,logFileResults.errorInjection,logFileResults.unionInjection,logFileResults.sqlInjectionAttempts,logFileResults.timebasedInjection,logFileResults.booleanInjection]
 
  let tlog= logFileResults.totalRequests
  let tsqli =  logFileResults.sqlInjectionAttempts
  let terror = syserror.count;

  const loginfo=''
  const logvalue=[];
  logvalue.push(tlog)
  logvalue.push(tsqli)
  logvalue.push(terror)



  //chart1 use
  const data= "'"+logFileResults.errorInjection+"','"+logFileResults.unionInjection+"','"+logFileResults.timebasedInjection+"','"+logFileResults.booleanInjection+"'"

  res.render("charts", {alog1:tlog,alog2:tsqli,alog3:terror,view:logFileResults.totalRequests,sqlin:logFileResults.sqlInjectionAttempts,err:syserror.count,datai: data,date:date,number:number,items:gettabledata,ips:ipnumber});
});


router.get('/allinj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const allsqli = logFileResults.sql_injectionarray;

  res.render("allsqli", {allsqli:allsqli});

})

router.get('/errinj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const errsqli = logFileResults.error_injectionarray;

  res.render("errinj", {errsqli:errsqli});

})

router.get('/booinj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const boosqli = logFileResults.boolean_Injectionarray;

  res.render("booinj", {boosqli:boosqli});

})

router.get('/booinj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const boosqli = logFileResults.boolean_Injectionarray;

  res.render("booinj", {boosqli:boosqli});

})

router.get('/timeinj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const timesqli = logFileResults.timebased_injectionarray;

  res.render("timeinj", {timesqli:timesqli});

})

router.get('/unioninj',function(req, res, next){
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const unionsqli = logFileResults.union_injectionarray;

  res.render("unioninj", {unionsqli:unionsqli});

})


router.get('/sendemail',(req, res)=>{
  logFileResults = analyzeLogFile('C:/xampp/apache/logs/access.log');
  const all = logFileResults.sqlInjectionAttempts;
  nowinj=all;
  if(oldinj==0){
    oldinj = nowinj;
  }
  if(oldinj>0){
    if(nowinj>oldinj){
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });
      oldinj = 0
    }
  }
  var tojson='{"result":"'+nowinj+'"}';
  var json = JSON.parse(tojson)
  res.send(JSON.stringify(json))

})


module.exports = router;