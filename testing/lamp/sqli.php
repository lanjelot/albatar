<?php
function mysql() {
  $db = new mysqli('localhost', 'root', 'Password1', 'anime_db');
  if ($db->connect_errno) {
    die('Failed to connect to MySQL');
  }
  $sql = 'SELECT * FROM anime';
  if (isset($_REQUEST['id'])) {
    $sql .= " WHERE id = ".$_REQUEST['id'];
  }
  $stmt = $db->query($sql);
  if (!$stmt) {
    die($db->error);
  }
  $rows = $stmt->fetch_all(MYSQLI_NUM);

  $stmt->close();
  $db->close();

  return $rows;
}

function mssql() {
  $db = sqlsrv_connect('mssql', array( "Database"=>"anime_db", "UID"=>"anime_user", "PWD"=>"Password1"));
  if (!$db) {
    die('Failed to connect to MSSQL');
  }
  $sql = 'SELECT * FROM anime';
  if (isset($_REQUEST['id'])) {
    $sql .= " WHERE id = ".$_REQUEST['id'];
  }
  $stmt = sqlsrv_query($db, $sql);
  if (!$stmt) {
    die(print_r(sqlsrv_errors(), true));
  }
  $rows = array();
  while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_NUMERIC)) {
    $rows[] = $row;
  }

  sqlsrv_free_stmt($stmt);
  sqlsrv_close($db);

  return $rows;
}

function oracle() {
  $db = oci_connect('anime_db', 'Password1', '//oracle/xe');
  if (!$db) {
    die('Failed to connect to Oracle');
  }
  $sql = 'SELECT * FROM anime';
  if (isset($_REQUEST['id'])) {
    $sql .= " WHERE id = ".$_REQUEST['id'];
  }
  $stid = oci_parse($db, $sql);
  oci_execute($stid);
  oci_fetch_all($stid, $rows, null, null, OCI_FETCHSTATEMENT_BY_ROW+OCI_NUM);
  
  oci_free_statement($stid);
  oci_close($db);

  return $rows;
}

function render($rows) {
  //var_dump($rows);
  echo '<html><body><h2>Yay animes!</h2><table border="0">'.count($rows).' rows fetched', PHP_EOL;
  foreach($rows as $row) {
    echo '<tr><td><a href="/?id='.$row[0].'">'.$row[0].'</a></td><td>'.$row[1].'</td></tr>', PHP_EOL;
  }
  echo '</table></body></html>', PHP_EOL;
}

$dbms = $_REQUEST['dbms'];

switch ($dbms) {
  case 'mysql':
$rows = mysql();
break;

  case 'mssql':
$rows = mssql();
break;

  case 'oracle':
$rows = oracle();
break;
}
render($rows);
?>
