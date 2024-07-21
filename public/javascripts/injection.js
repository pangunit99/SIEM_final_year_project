const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const logParser = require('@slaughtr/apache-log-parser');
var Chart = require('chart.js');

const SQL_INJECTION_REGEX = /(\b(UNION|SELECT|UPDATE|DELETE|INSERT|WHERE)\b|\b(?:--|\/\*)\s)/i;
const ERROR_INJECTION = /('|--|%|--|\)|ORDER BY|GROUP BY)/i;
const UNION_INJECTION = /(UNION|SELECT|ALERT|DROP)/i;
const Time_based = /(SLEEP|BENCHMARK)/i;
const BOOLEAN_based = /(AND|ASCII|LENGTH)/i;
const Privilege_Escalation = /(USER_PRIVILEGES|cmd|whoami|EXEC|INSERT)/i;

function analyzeLogFile(logFilePath) {
  const logEntries = fs.readFileSync(logFilePath, 'utf-8').split('\n');
  const results = {
    totalRequests: 0,

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
  const printontable = [];
  logEntries.forEach((entry) => {
    if (entry) {
      results.totalRequests++;
      if (SQL_INJECTION_REGEX.test(entry)) {
        if(ERROR_INJECTION.test(entry)){
          results.errorInjection++;
          results.error_injectionarray.push(logParser({ string: entry }));
        }else  if(UNION_INJECTION.test(entry)){
          results.unionInjection++;
          results.union_injectionarray.push(logParser({ string: entry }));
        }else if(Time_based.test(entry)){
          results.timebasedInjection++;
          results.timebased_injectionarray.push(logParser({ string: entry }));
        }else if(BOOLEAN_based.test(entry)){
          results.booleanInjection++;
          results.boolean_Injectionarray.push(logParser({ string: entry }));
        }else{
          results.sqlInjectionAttempts++;
          results.sql_injectionarray.push(logParser({ string: entry }))          
        }
      }
    }
  });
  console.log(printontable);
  return results;
}

module.exports = {analyzeLogFile}