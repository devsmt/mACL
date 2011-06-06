<?php
/*
porpuse:
    determine if a user can access a resource and eventually can do an action on the resource
*/
class ACL {
    public static function isAllowed(ArrayAccess $ACL, $user_id, array $roles, $resource_id, $action = '*') {
        $allowed = ACL::userIsAllowed($ACL, $user_id, $resource_id, $action);
        if (!$allowed) {
            foreach ($roles as $role) {
                $allowed = ACL::roleIsAllowed($ACL, $role, $resource_id, $action);
                if ($allowed) {
                    break;
                }
            }
        }
        return $allowed;
    }
    /*
    determina se, l'utente selezionato ha permessi per la risorsa+azione secondo 
    i dati contenuti nella lista $ACL
    $resource_id può essere qualunque cosa, controllers, tabelle, files
    */
    public static function userIsAllowed(ArrayAccess $ACL, $user_id, $resource_id, $action = '*') {
        $allowed = false;
        if ($user_id === '__groups__') {
            die("non puoi chiamre ACL::userIsAllowed di un utente con id '__groups__'! ");
        }
        if (!is_string($resource_id) || empty($resource_id)) {
            die("non puoi chiamre ACL::userIsAllowed per una risorsa vuota:" . var_dump($resource_id));
        }
        if (!is_string($user_id) || empty($user_id)) {
            die("non puoi chiamre ACL::userIsAllowed per uno user vuoto:" . var_dump($resource_id));
        }
        // if it is not specified what to access, assume accessing all
        if (!is_string($action)) {
            $action = '*';
        }
        if (isset($ACL[$user_id])) {
            if ($ACL[$user_id] === '*' || in_array('*', $ACL[$user_id])) {
                // superadmin can access all resources
                $allowed = true;
            } elseif (isset($ACL[$user_id][$resource_id])) {

                if (isset($ACL[$user_id][$resource_id]['*'])) {
                    $allowed = true;
                } else {
                    if (in_array($action, $ACL[$user_id][$resource_id])) {
                        $allowed = true;
                    } else {
                        $allowed = false;
                    }
                }
            }
        }
        return $allowed;
    }
    /*
    Role based access list
    */
    public static function roleIsAllowed(ArrayAccess $ACL, $role, $resource_id, $action = '*') {
        $allowed = false;
        // if is not clear what the action will be, assume "all" actions
        if (!is_string($action)) {
            $action = '*';
        }
        // if acl doesnt know obout groups...
        if (!isset($ACL['__groups__'])) {
            return false;
        }
        $GACL = $ACL['__groups__'];
        if (isset($GACL[$role])) {
            // superadmin, can access all resources
            if ($GACL[$role] === '*' || in_array('*', $GACL[$role])) {
                $allowed = true;
            } elseif (isset($GACL[$role][$resource_id])) {
                // if is admin, and than has all privileges over the resource
                // or har the specific right
                if ($GACL[$role][$resource_id] == '*' || in_array('*', $GACL[$role][$resource_id]) || in_array($action, $GACL[$role][$resource_id])) {
                    $allowed = true;
                } else {
                    $allowed = false;
                }
            }
        } 
        
        return $allowed;
    }
}
/*
   the simplest, but general enough, data storage possible
*/
class ACL_starage_array implements ArrayAccess {
    private $data = array();
    public function __construct($data) {
        $this->data = $data;
    }
    public function offsetExists($offset) {
        return isset($this->data[$offset]);
    }
    public function offsetGet($offset) {
        return isset($this->data[$offset]) ? $this->data[$offset] : null;
    }
    // write methods, not needed for the moment
    public function offsetSet($offset, $value) {
        //    if (is_null($offset)) {
        //        $this->data[] = $value;
        //    } else {
        //        $this->data[$offset] = $value;
        //    }
        
    }
    public function offsetUnset($offset) {
        //    unset($this->data[$offset]);
        
    }
}
