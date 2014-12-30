<?php
/**
 * Created by PhpStorm.
 * User: api
 * Date: 12/22/2014
 * Time: 11:49 AM
 */

namespace Outbox\AtTaskConnector;


class Formatter {
    /**
     * Converts objects returned into arrays. This is necessary when returning complex objects.
     * For example, an object returned from a search using a cross-object reference cannot be displayed using methods to display simple objects...
     *   /api/task/search?fields=project:name
     *   /api/task/search?fields=DE:Parameter Name
     * Both contain colons, which will result in a stdClass error when using the methods to reference simple objects.
     * The function below provides a way to convert the 'project:name' object into a usuable array,
     *   i.e., $task['project:name'] can be used by placing the returned object into the function.
     */
    public static function objectToArray ($object) {
        if (!is_object($object) && !is_array($object)) {
            return $object;
        }
        if (is_object($object)) {
            $object = get_object_vars($object);
        }
        return array_map(['self','objectToArray'], $object);
    }

    /**
     * Converts ISODATE to unix date
     * 1984-09-01T14:21:31Z
     * i.e., $plannedStartDate = tstamptotime($task['plannedStartDate']);
     */
    public static function tstamptotime ($tstamp) {
        sscanf($tstamp, "%u-%u-%uT%u:%u:%uZ", $year, $month, $day, $hour, $min, $sec);
        return mktime($hour, $min, $sec, $month, $day, $year);
    }

    public static function erase_val (&$myarr) {
        $myarr = array_map(create_function('$n', 'return null;'), $myarr);
    }
}