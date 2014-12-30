<?php

namespace Outbox\AtTaskConnector;

/*
 * Copyright (c) 2010 AtTask, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * Revised by Ryan Bowcutt to:
 * make compatible with v4.0 and v5.0 of the API
 * make the post function able to set array fields, boolean fields, secondary objects, and collections while inserting a record
 * make the search function work with any $$FIRST and $$LIMIT parameters, no matter how large
 * make the search function merge paginated search results in the proper order
 * remove the report function's handling of $$FIRST and $$LIMIT parameters since they are not applicable
 * make the download and upload functions work on the DocumentVersion and Avatar objects
 * make the download and upload functions work with very large files
 * make the download function determine the URL based on the objCode and objID
 * make the action function accept multiple arguments
 * make the whoami function more efficient
 * make the login function able to retrieve our API key instead of our session ID if desired
 * create a getSessionIDs function that retrieves the session IDs of other users (in order to impersonate them)
 * create a getApiKeys function that retrieves the API keys of other users (in order to impersonate them)
 * create a setting ($authType) that determines whether session IDs or API keys should be used in calls (default is session IDs)
 * add a function for manually setting the session ID or API key for all future calls (setAuthToken)
 * make the session ID or API key automatically revert to our own after a call with another user's ID/key is made
 * enable batch operations
 * enable bulk updates
 * make the formatting of the code more consistent
 * change where slashes are added to paths
 */

// API Version
set_time_limit(0);

/**
 * StreamClient class
 *
 * @throws RestAPIClientException
 * @package StreamRestClient
 */
class RestAPIClient {
	
	const
		// Supported request methods
		METH_DELETE   = 'DELETE',
		METH_GET      = 'GET',
		METH_POST     = 'POST',
		METH_PUT      = 'PUT';
	
	const
		// Well known paths
		PATH_LOGIN    = 'login',
		PATH_LOGOUT   = 'logout',
		PATH_SEARCH   = '/search',
		PATH_REPORT   = '/report',
		PATH_COUNT    = '/count',
		PATH_BATCH    = 'batch',
		PATH_METADATA = 'metadata',
		
		// Screenscrap Objects
		PATH_ATTASK   = '/attask',
		
		// Screenscrap Actions
		PATH_DELETE   = 'Delete.cmd', // Delete Mode
		PATH_OPEN     = 'Open.cmd', // Edit Mode
		PATH_EDIT     = 'Edit.cmd', // Put Mode
		PATH_ADD      = 'Add.cmd', // Post Mode
		PATH_VIEW     = 'View.cmd'; // View Mode
	
	public
		$handle       = null,
		$hostname     = null,
		$domain       = null,
		$debug        = null,
		$batch        = false,
		$queue        = null,
		$atomic       = false,
		$bulk         = false,
		$bulkQueue    = null,
		$mySessionID  = null,
		$myApiKey     = null,
		$authToken    = null, // Session ID or API key, depending on $authType
		$authType     = 'sessionID'; // Can be changed to 'apiKey' to use an API key instead of a session ID in each call. This setting also affects how some functions work.

	private
		$apiUrls = [
			'1.0' => '/attask/api/v1.0',
			'2.0' => '/attask/api/v2.0',
			'3.0' => '/attask/api/v3.0',
			'4.0' => '/attask/api/v4.0',
			'5.0' => '/attask/api/v5.0',
			'internal' => '/attask/api-intenal',
			'default' => '/attask/api'
		],
		$httpType = 'https';
	
	/** 
	 * Creates an instance of the client
	 *
	 * @param  string $hostname
	 * @return void
	 */
	public function __construct ($hostname, $version = '5.0') {
		if (strpos($hostname, 'https://') !== false) {
			$hostname = str_replace('https://', '', $hostname);
			$hostname = str_replace('/attask', '', $hostname);		
		} 
		
		$this->domain = $hostname; // Store the domain information for use outside the API context

		if(isset($this->apiUrls[$version])) {
			$this->hostname = $this->httpType . '://' . $hostname . $this->apiUrls[$version];
		} else {
			$this->hostname = $this->httpType . '://' . $hostname . '/attask/api';
		}

		$this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
		
		// Initialize cURL
		if (is_null($this->handle)) {
			$this->handle = curl_init();
			curl_setopt($this->handle, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($this->handle, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt($this->handle, CURLOPT_CONNECTTIMEOUT, 5);
			curl_setopt($this->handle, CURLOPT_TIMEOUT, 240);
			curl_setopt($this->handle, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($this->handle, CURLOPT_POST, true);
			curl_setopt($this->handle, CURLOPT_BUFFERSIZE, 128000);
			curl_setopt($this->handle, CURLOPT_SSLVERSION, 4); // Might need to be 3 for some instances of AT
		}
	}

	/**
	 * Destroys an instance of the client
	 *
	 * @return void
	 */
	public function __destruct () {
		// Close cURL
		if (!is_null($this->handle)) {
			curl_close($this->handle);
			$this->handle = null;
		}
	}
	
	/**
	 * Sets the session ID or API key (depending on $authType) to be used for all future calls (not usually needed)
	 *
	 * @param  string $IDorKey
	 * @return void
	 */
    public function setAuthToken($IDorKey) {
		if ($this->authType == 'sessionID') {
			$this->mySessionID = $IDorKey;
		}
		elseif ($this->authType == 'apiKey') {
			$this->myApiKey = $IDorKey;
		}
		$this->authToken = $IDorKey;
    }
	
	/**
	 * Create Object outside of the API
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  array $params
	 * @return array
	 */
	public function atAdd ($objCode, $params = '') {
		return $this->atRequest(self::PATH_ATTASK . '/' . $objCode . self::PATH_ADD, $params);
	}
	
	private function atRequest ($path, $params) {
		$query = 'secure_code=' . $this->authToken;
		$query .= '&sessionID=' . $this->authToken;
		//$query = 'username=' . $this->username;
		//$query .= '&password=' . $this->password;
		
		$cookie = 'sessionID=' . $this->authToken . ';path=/attask';
		
		if (!is_null($params)) {
			$query .= '&' . http_build_query($params);
		}
		
		// Set dynamic cURL options
		curl_setopt($this->handle, CURLOPT_URL, $this->httpType . '://' . $this->domain . $path);
		curl_setopt($this->handle, CURLOPT_COOKIE, $cookie);
		curl_setopt($this->handle, CURLOPT_COOKIESESSION, TRUE); 
		curl_setopt($this->handle, CURLOPT_COOKIEFILE, $this->tmpDir . "cookiefile");
		curl_setopt($this->handle, CURLOPT_COOKIEJAR, $this->tmpDir . "cookiefile");
		curl_setopt($this->handle, CURLOPT_POSTFIELDS, urlEncode($query));
		if ($this->debug) {
			echo '<br/>----Call----' . $this->httpType . '://' . $this->domain . $path . '?' . $query . PHP_EOL;
		}
		
		// Execute request
		if (!($response = curl_exec($this->handle))) {
			throw new RestAPIClientException(curl_error($this->handle));
			//print_r(curl_getinfo($this->handle));
		}
		var_dump($response);
		
		exit;
		
		$result = json_decode($response);
		
		// Verify result
		if (isset($result->error)) {
			throw new RestAPIClientException($result->error->message);
		}
		elseif (!isset($result->data)) {
			$result = json_decode($response);
			// Verify result
			if (isset($result->error)) {
				throw new RestAPIClientException($result->error->message);
			}
			elseif (!isset($result->data)) {
				throw new RestAPIClientException('Invalid response from server');
			}
		}

		if ($this->debug) {
			echo '----Results----<br/>';
			print_r($result->data);
			echo '-------------------------------------------------' . PHP_EOL;
		}
		return Formatter::objectToArray($result->data);
	}
	
	// END ATREQUESTS
	
	/**
	 * Login to AtTask
	 *
	 * @throws RestAPIClientException
	 * @param  string $username
	 * @param  string $password
	 * @return array
	 */
	public function login ($username, $password) {
		if ($this->authType == 'sessionID') { // Login and get a session ID
			if ($username && $password) {
				$this->username = $username;
				$this->password = $password;
			}
			return $this->request(self::PATH_LOGIN, array('username' => $username, 'password' => $password), null, self::METH_GET);
		}
		elseif ($this->authType == 'apiKey' && !isset($this->myApiKey)) { // Get our API key
			if (file_exists('APIKeys0.txt')) {
				$file = 'APIKeys0.txt';
			}
			elseif (file_exists('APIKeys1.txt')) {
				$file = 'APIKeys1.txt';
			}
			else {
				// Get a session ID and then get our API key
				if ($username && $password) {
					$this->username = $username;
					$this->password = $password;
					$this->authType = 'sessionID';
					$this->request(self::PATH_LOGIN, array('username' => $username, 'password' => $password), null, self::METH_GET);
					$this->authType = 'apiKey';
				}
				$this->getApiKeys(true);
				$file = 'APIKeys0.txt';
			}
			$this->setAuthToken(json_decode(file_get_contents($file), true)['myApiKey']);
		}
	}
	
	/**
	 * Logout from AtTask
	 *
	 * @throws RestAPIClientException
	 * @return bool
	 */
	public function logout () {
		return $this->request(self::PATH_LOGOUT, array('sessionID' => $this->mySessionID), null, self::METH_GET)['success'];
	}
	
	/**
	 * Retrieve the session IDs of multiple users (in order to impersonate them) and store them in a text file.
	 * To use session IDs, set $this->authToken to a session ID before each call that impersonates another user.
	 *
	 * @throws RestAPIClientException
	 * @param  array $usernames (active users only)
	 * @param  bool $overwrite (overwrite text file or add to existing?)
	 * @param  int $fileNum [optional] (e.g., if creating a second file of session IDs (like for another instance of AT), $fileNum = 2)
	 * @return array
	 */
	public function getSessionIDs ($usernames, $overwrite, $fileNum = 1) {
		$fileName = 'SessionIDs' . $fileNum . '.txt';
		
		if ($overwrite) {
			// Retrieve a fresh session ID for ourselves and the current time and load them into the array
			$this->login($this->username, $this->password);
			$arr = array('complete' => false, 'timeOfGeneration' => time(), 'mySessionID' => $this->mySessionID, 'sessionIDs' => array());
		}
		else {
			// Load array with current file contents
			$sessIDsArr = json_decode(file_get_contents($fileName), true);
			$sessionIDs = $sessIDsArr['sessionIDs'];
			$arr = array('complete' => false, 'timeOfGeneration' => $sessIDsArr['timeOfGeneration'], 
			'mySessionID' => $sessIDsArr['mySessionID'], 'sessionIDs' => $sessionIDs);
		}
		
		// Retrieve others' session IDs. Individual calls are just as fast and often much faster (and more reliable) than batching for this.
		foreach ($usernames as $username) {
			try {
				$login = $this->login($username, null);
				$sessionIDs[$login['userID']] = $login['sessionID'];
			}
			catch (Exception $e) {
				$arr['sessionIDs'] = $sessionIDs;
				file_put_contents($fileName, json_encode($arr));
				
				if (strpos($e->getMessage(), 'no user found with username') === false/* && strpos($e->getMessage(), 'not set up yet') === false*/) {
					throw $e;
				}
			}
		}
		$arr['complete'] = true;
		$arr['sessionIDs'] = $sessionIDs;
		
		// Export all session IDs to a text file in the local directory and return them
		file_put_contents($fileName, json_encode($arr));
		return $arr;
	}
	
	/**
	 * Retrieve our API key and the keys of other users (in order to impersonate them) and store them in a text file. Retrieving keys of other users 
	 * requires a SessionIDs#.txt file with unexpired session IDs, so the getSessionIDs function must be used first.
	 * To use API keys, set $this->authToken to an API key before each call that impersonates another user.
	 *
	 * @throws RestAPIClientException
	 * @param  bool $overwrite (overwrite text file or add to existing?) - if false, will only add new users from SessionIDs#.txt
	 * @param  int $fileNum [optional] (e.g., if $fileNum = 2, API keys will be generated for the users listed in SessionIDs2.txt and saved in 
	 * APIKeys2.txt) If $fileNum = 0, SessionIDs#.txt is not needed and APIKeys0.txt will be created with only our own API key. 
	 * @return array
	 */
	public function getApiKeys ($overwrite, $fileNum = 0) {
		$fileName1 = 'SessionIDs' . $fileNum . '.txt';
		$fileName2 = 'APIKeys' . $fileNum . '.txt';
		
		$currentAuthType = $this->authType;
		$this->authType = 'sessionID';
		
		if ($overwrite || $fileNum == 0) {
			// Retrive our API key and the current time and load them into the array
			$myUserID = $this->whoami(array('ID'))[0]['ID'];
			$myApiKey = $this->action('User', $myUserID, 'getApiKey')['result'];
			$apiKeys = array();
			$arr = array('complete' => false, 'timeOfGeneration' => time(), 'myApiKey' => $myApiKey, 'apiKeys' => $apiKeys);
		}
		else {
			// Load array with current file contents
			$apiKeysArr = json_decode(file_get_contents($fileName2), true);
			$apiKeys = $apiKeysArr['apiKeys'];
			$arr = array('complete' => false, 'timeOfGeneration' => $apiKeysArr['timeOfGeneration'], 
			'myApiKey' => $apiKeysArr['myApiKey'], 'apiKeys' => $apiKeys);
		}
		
		// Retrive session IDs from SessionIDs#.txt
		$sessionIDs = ($fileNum > 0) ? json_decode(file_get_contents($fileName1), true)['sessionIDs'] : array();
		
		// Retrieve others' API keys
		foreach ($sessionIDs as $userID => $sessionID) {
			if ($overwrite || !isset($apiKeys[$userID])) { // If false, only add new users
				try {
					$this->authToken = $sessionID;
					$apiKeys[$userID] = $this->action('User', $userID, 'getApiKey')['result'];
				}
				catch (Exception $e) {
					$arr['apiKeys'] = $apiKeys;
					file_put_contents($fileName2, json_encode($arr));
					
					throw $e;
				}
			}
		}
		$arr['complete'] = true;
		$arr['apiKeys'] = $apiKeys;
		
		$this->authType = $currentAuthType;
		
		// Export all API keys to a text file in the local directory and return them
		file_put_contents($fileName2, json_encode($arr));
		return $arr;
	}
	
	/**
	 * Get details about the curent user
	 *
	 * @throws RestAPIClientException
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function whoami ($fields = null) {
		return $this->request('user/search', array('ID'=>'$$USER.ID'), $fields, self::METH_GET);
	}
	
	/**
	 * Searches for all records that match a given query. Accepts any $$FIRST and $$LIMIT parameters. If these parameters are omitted, all records are found.
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  array $query
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function search ($objCode, $query, $fields = null) {
		// Set $$FIRST and $$LIMIT parameters
		if (!isset($query['$$FIRST'])) {
			$query['$$FIRST'] = 0;
		}
		if (!isset($query['$$LIMIT'])) {
			// Count records if object can be counted
			$count = ($objCode != 'UserPrefValue' && $objCode != 'CustomerPreferences') ? $this->atcount($objCode, $query)['count'] : $query['$$FIRST'];
			$query['$$LIMIT'] = $count - $query['$$FIRST'];
		}
		
		if ($query['$$LIMIT'] <= 2000) {
			return $this->request($objCode . self::PATH_SEARCH, (array) $query, $fields, self::METH_GET);
		}
		else {
			// Paginate the search; i.e., make multiple searches and combine the results
			$loops = ceil($query['$$LIMIT'] / 2000);
			$lastLimit = $query['$$LIMIT'] % 2000;
			$query['$$LIMIT'] = '2000';
			$results = array();
			
			for ($i = 0; $i < $loops; $i++) {
				if ($i == $loops - 1) {
					$query['$$LIMIT'] = $lastLimit;
				}
				$results = array_merge($results, $this->request($objCode . self::PATH_SEARCH, (array) $query, $fields, self::METH_GET));
				$query['$$FIRST'] += 2000;
			}
			return $results;
		}
	}
	
	/**
	 * Reports for all records that match a given query
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  array $query
	 * @return array
	 */
	public function report ($objCode, $query) {
		return $this->request($objCode . self::PATH_REPORT, (array) $query, null, self::METH_GET);
	}
	
	/**
	 * Counts total that would be returned for a given query
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  array $query
	 * @return array
	 */
	public function atcount ($objCode, $query) {
		return $this->request($objCode . self::PATH_COUNT, (array) $query, null, self::METH_GET);
	}
	
	/**
	 * Named Queries total that would be returned for a given query
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $path
	 * @param  array $query
	 * @return array
	 */
	public function namedquery ($objCode, $path, $query, $fields = null) {
		return $this->request($objCode . self::$path, (array) $query, $fields, self::METH_GET);
	}
	
	/**
	 * Batch Queries total that would be returned for a given query
	 *
	 * @throws RestAPIClientException
	 * @param  array $query
	 * @return array
	 */
	public function batch ($query) {
		return $this->request(self::PATH_BATCH, (array) $query, null, self::METH_GET);
	}
	
	/**
	 * Retrieves an object by ID
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $objID
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function get ($objCode, $objID, $fields = null) {
		return $this->request($objCode . '/' . $objID, null, $fields, self::METH_GET);
	}
	
	/**
	 * Performs an action on an object
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $objID
	 * @param  string $action
	 * @param  array $arguments [optional]
	 * @return array
	 */
	public function action ($objCode, $objID, $action, $arguments = null) {
		if ($arguments == null) {
			return $this->request($objCode . '/' . $objID . '/' . $action, null, null, self::METH_PUT);
		}
		else {
			return $this->request($objCode . '/' . $objID . '/' . $action, array('updates' => json_encode($arguments)), null, self::METH_PUT);
		}
	}
	
	/**
	 * Inserts a new object
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  array $message
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function post ($objCode, $message, $fields = null) {
		//return $this->request($objCode, (array) $message, $fields, self::METH_POST); // Original
		return $this->request($objCode, array('updates' => json_encode($message)), $fields, self::METH_POST); //New and improved
	}
	
	/**
	 * Sets a flag indicating that all subsequent put requests should be queued for a single bulk update
	 *
	 * @return void
	 */
	public function bulkStart () {
		$this->bulk = true;
		$this->bulkQueue = array();
	}
	
	/**
	 * Executes the queued put requests in a bulk update
	 *
	 * @param  string $objCode
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function bulkEnd ($objCode, $fields = null) {
		// Validate request before unnecessarily taxing the server
		if (count($this->bulkQueue) == 0) {
			throw new RestAPIClientException('Bulk updates must specify at least one \'updates\' parameter');
		}
		return $this->put($objCode, null, $this->bulkQueue, $fields);
	}
	
	/**
	 * Edits one or more existing records
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $objID
	 * @param  array $message
	 * @param  array $fields [optional]
	 * @return array
	 */
	public function put ($objCode, $objID, $message, $fields = null) {
		// Bulk update - updates=[{"ID":"abc123","description":"val1"},{"ID":"def456","name":"val2"}]
		if ($this->bulk) {
			if ($objID != null) {
				$this->bulkQueue[] = array_merge(array('ID' => $objID), $message);
			}
			else {
				$this->bulk = false;
				$this->bulkQueue = null;
				return $this->request($objCode, array('updates' => json_encode($message)), $fields, self::METH_PUT);
			}
		}
		// Ordinary update
		else {
			return $this->request($objCode . '/' . $objID, array('updates' => json_encode($message)), $fields, self::METH_PUT);
		}
	}
	
	/**
	 * Sets audit flags on an existing object
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $objID
	 * @param  array $fields [optional]
	 * @return array or false
	 */
	public function audit ($objCode, $objID, $message = null, $fields = null) {
		$objCode = strtoupper($objCode);
		if (in_array($objCode, array('PORTFOLIO', 'PORT', 'PROGRAM', 'PRGM', 'PROJECT',  'PROJ', 'TASK', 'ISSUE', 'OPTASK'))) {
			$message = '{"auditTypes": ["AA", "GE", "ST", "SC"]}';
			return $this->request($objCode . '/' . $objID, array('updates' => $message), null, self::METH_PUT);
		}
		else {
			return false;
		}
	}
	
	/**
	 * Deletes an object
	 *
	 * @throws RestAPIClientException
	 * @param  string $objCode
	 * @param  string $objID
	 * @param  bool $force [optional]
	 * @return bool
	 */
	public function delete ($objCode, $objID, $force = false) {
		return $this->request($objCode . '/' . $objID, array('force' => $force), null, self::METH_DELETE)['success'];
	}
	
	/**
	 * Retrieves API metadata for an object
	 *
	 * @throws RestAPIClientException
	 * @param  {string|null} $objCode [optional]
	 * @return array
	 */
	public function metadata ($objCode = null) {
		// Build request path
		$path = '';
		if (!empty($objCode)) {
			$path .= $objCode . '/';
		}
		$path .= self::PATH_METADATA;
		
		return $this->request($path, null, null, self::METH_GET);
	}
	
	/**
	 * Uploads a document to an object
	 * Same as <input type="file" name="file_box">
	 *
	 * @param  string $objCode = 'DOCU', 'DOCV', 'AVATAR', 'Document', 'DocumentVersion', or 'Avatar'
	 * @param  string $file (e.g., '@C:/Temp/MyDocument.docx' OR '@/var/chroot/home/content/39/7649239/html/tmp/MVC-002X.jpg')
	 * @param  array $message - if $objCode = 'AVATAR', include user ID in $message (e.g., {"ID":"(userID)"})
	 * @param  array $fields [optional]
	 * @throws RestAPIClientException
	 * @return array
	 */
	public function upload ($objCode, $file, $message, $fields = null) {
		// Build request path
		$path = '/upload?' . $this->authType . '=' . $this->authToken;
		
		// Set dynamic cURL options
		curl_setopt($this->handle, CURLOPT_URL, $this->hostname . $path);
		curl_setopt($this->handle, CURLOPT_POSTFIELDS, array('uploadedFile' => $file));
		curl_setopt($this->handle, CURLOPT_TIMEOUT, 1200);
		
		if ($this->debug) {
			echo '<br/>----Call----' . $this->hostname . $path . PHP_EOL;
		}
		
		// Execute request
		if (!($response = curl_exec($this->handle))) {
			throw new RestAPIClientException(curl_error($this->handle));
		}
		$result = json_decode($response);
		
		// Verify result
		if (isset($result->error)) {
			throw new RestAPIClientException($result->error->message);
		}
		elseif (!isset($result->data)) {
			// Trying the query again...
			if (!($response = curl_exec($this->handle))) {
				throw new RestAPIClientException(curl_error($this->handle));
			}
			$result = json_decode($response);
			// Verify result
			if (isset($result->error)) {
				throw new RestAPIClientException($result->error->message);
			}
			elseif (!isset($result->data)) {
				// Trying the query again...
				if (!($response = curl_exec($this->handle))) {
					throw new RestAPIClientException(curl_error($this->handle));
				}
				$result = json_decode($response);
				// Verify result
				if (isset($result->error)) {
					throw new RestAPIClientException($result->error->message);
				}
				elseif (!isset($result->data)) {
					throw new RestAPIClientException('Invalid response from server');
				}
			}
		}
		
		if ($this->debug) {
			echo '----Results Upload----<br/>';
			print_r($result->data);
			echo '-------------------------------------------------' . PHP_EOL;
		}
		$h = Formatter::objectToArray($result->data);
		$message['handle'] = $h['handle'];
		
		$objCode = strtoupper($objCode);
		if (in_array($objCode, array('DOCU', 'DOCV', 'DOCUMENT', 'DOCUMENTVERSION'))) {
			return $this->request($objCode, array('updates' => json_encode($message)), $fields, self::METH_POST);
		}
		elseif ($objCode == 'AVATAR') {
			$handle = json_encode(array('handle' => $message['handle']));
			return $this->request('Avatar/' . $message['ID'], array('updates' => $handle), $fields, self::METH_PUT); // Include user ID in $message
		}
		else {
			throw new RestAPIClientException('objCode must be "DOCU", "DOCV", "AVATAR", "Document", "DocumentVersion", or "Avatar"');
		}
	}
	
	/**
	 * Downloads a file and stores it in the temp folder
	 *
	 * @param  string $objCode = 'DOCU', 'DOCV', 'AVATAR', 'Document', 'DocumentVersion', or 'Avatar'
	 * @param  string $objID
	 * @param  string $file [optional] (e.g., 'MyDocument.docx')
	 * @throws RestAPIClientException
	 * @return void (formerly returned file handle)
	 */
	public function download ($objCode, $objID, $file = 'File') {
		// Build request path
		$objCode = strtoupper($objCode);
		if ($objCode == 'DOCU' || $objCode == 'DOCUMENT') {
			$url = '/document/download?ID=';
		}
		elseif ($objCode == 'DOCV' || $objCode == 'DOCUMENTVERSION') {
			$url = '/document/download?versionID=';
		}
		elseif ($objCode == 'AVATAR') {
			$url = '/user/avatar?ID=';
		}
		else {
			throw new RestAPIClientException('objCode must be "DOCU", "DOCV", "AVATAR", "Document", "DocumentVersion", or "Avatar"');
		}
		$path = $url . $objID . '&' . $this->authType . '=' . $this->authToken;
		
		$fp = fopen ( $this->tmpDir . $file, 'w+');
		// Set dynamic cURL options
		curl_setopt($this->handle, CURLOPT_URL, $this->httpType . '://' . $this->domain . $path);
		curl_setopt($this->handle, CURLOPT_FILE, $fp);
		curl_setopt($this->handle, CURLOPT_TIMEOUT, 1200);
		
		if ($this->debug) {
			echo '<br/>----Call----' . $this->httpType . '://' . $this->domain . $path . PHP_EOL;
		}
		
		// Execute request
		if (!($response = curl_exec($this->handle))) {
			throw new RestAPIClientException(curl_error($this->handle));
		}
		// Undo CURLOPT_FILE before returning to ordinary calls
		curl_setopt($this->handle, CURLOPT_RETURNTRANSFER, true);
		
		fflush($fp);
		//return $fp;
	}
	
	/**
	 * Sets a flag indicating that all subsequent calls to the API should be queued for a single request
	 *
	 * @return void
	 */
	public function batchStart () {
		$this->batch = true;
		$this->queue = array();
	}
	
	/**
	 * Executes the queued batch of requests
	 *
	 * @throws RestAPIClientException
	 * @param  bool $atomic - when true, if any request in the batch fails, they all fail
	 * @return array
	 */
	public function batchEnd ($atomic = false) {
		$this->atomic = $atomic;
		// Validate request before unnecessarily taxing the server
		if (empty($this->queue)) {
			throw new RestAPIClientException('Batch operations must specify at least one \'uri\' parameter');
		}
		return $this->request(self::PATH_BATCH, $this->queue, null, 'batchEnd');
	}
	
	/**
	 * Performs the request to the server
	 *
	 * @throws RestAPIClientException
	 * @param  string $path
	 * @param  array $params
	 * @param  array $fields [optional]
	 * @param  string $method
	 * @return array or null
	 */
	private function request ($path, $params, $fields = null, $method) {
		if ($this->batch) {
			if ($method != 'batchEnd') {
				// Create request and add it to queue if running in batch mode
				if (!empty($fields)) {
					$params['fields'] = implode(',', $fields);
				}
				$this->queue[] = $path . '?method=' . $method . '%26' . http_build_query($params, null, '%26');
				return null;
			}
			else {
				$query = $this->authType . '=' . $this->authToken . '&atomic=' . var_export($this->atomic, true) . '&uri=' . implode('&uri=', $this->queue);
				
				// Reset batch properties
				$this->batch = false;
				$this->queue = null;
				$this->atomic = false;
			}
		}
		else {
			$query = $this->authType . '=' . $this->authToken . '&method=' . $method;
			
			if (!empty($fields)) {
				$params['fields'] = implode(',', $fields);
			}
			if (!empty($params)) {
				$query .= '&' . http_build_query($params);
			}
			if ($method == 'POST') {
				$objCode = strtoupper($path);
				if (in_array($objCode, array('UIVIEW', 'UIVW', 'PORTALSECTION', 'PTLSEC'))) {
					$query = str_replace('%5B%5D', '%7B%7D', $query);
				}
			}
		}
		
		// Set dynamic cURL options
		curl_setopt($this->handle, CURLOPT_URL, $this->hostname . '/' . $path);
		curl_setopt($this->handle, CURLOPT_POSTFIELDS, $query);
		
		if ($this->debug) {
			echo '<br/>----Call----' . $this->hostname . '/' . $path . '?' . urlDecode($query) . PHP_EOL;
			//echo '<br/>----Call----' . $this->hostname . '/' . $path . '?' . $query . PHP_EOL;
		}
		
		// Execute request
		if (!($response = curl_exec($this->handle))) {
			throw new RestAPIClientException(curl_error($this->handle));
			//print_r(curl_getinfo($this->handle));
		}
		//var_dump($response);
		$result = json_decode($response);
		
		// Verify result
		if (isset($result->error)) {
			throw new RestAPIClientException($result->error->message);
		}
		elseif (!isset($result->data)) {
			// Trying the query again...
			if (!($response = curl_exec($this->handle))) {
				throw new RestAPIClientException(curl_error($this->handle));
			}
			$result = json_decode($response);
			// Verify result
			if (isset($result->error)) {
				throw new RestAPIClientException($result->error->message);
			}
			elseif (!isset($result->data)) {
				// Trying the query again...
				if (!($response = curl_exec($this->handle))) {
					throw new RestAPIClientException(curl_error($this->handle));
				}
				$result = json_decode($response);
				// Verify result
				if (isset($result->error)) {
					throw new RestAPIClientException($result->error->message);
				}
				elseif (!isset($result->data)) {
					throw new RestAPIClientException('Invalid response from server');
				}
			}
		}
		
		// Manage the session
		if ($path == self::PATH_LOGIN && $params['password'] != null) { // If it's a non-impersonation login...
			$this->mySessionID = $result->data->sessionID;
		}
		elseif ($path == self::PATH_LOGOUT) {
			$this->mySessionID = null;
		}
		if ($this->authType == 'sessionID') {
			$this->authToken = $this->mySessionID; // Revert the active session ID to our own
		}
		elseif ($this->authType == 'apiKey') {
			$this->authToken = $this->myApiKey; // Revert the active API key to our own
		}
		
		if ($this->debug) {
			echo '<br/>----Results----<br/>';
			print_r($result->data);
			echo '-------------------------------------------------' . PHP_EOL;
		}
		$t = Formatter::objectToArray($result->data);
		if (isset($t['null'])) { // Fix an error that retuns a null array at the top
			return $t['null'];
		}
		else {
        	return $t;
		}
	}
	
// END of Class
}