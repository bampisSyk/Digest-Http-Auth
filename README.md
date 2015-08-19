# Digest-Http-Auth
This is a simple nodeJS module that allows to connect to servers with Digest authentication via the htt.get 

# Simple use case

var digestAuth = require('./digestAuth');

//Response with custom digestAuth library
	//-----------------------------
	digestAuth.getDataWithAuth(username,password,url,'GET',function(data){	
		var req = http.get(data, function(res) {

		 res.on('data', function (chunk) {
		    console.log('BODY: ' + chunk);
		    response.send(chunk);
		 });
		});
		req.on('error', function(e) {
		  console.log('Something went wrong with the request: ' + e.message);
		});
		req.end();
});
	//-----------------------------
