# Powershell module to compare 2 hashtables
# This checks to see if all the keys match
# (no missing keys from either one)
# It will then compare the values to see if these match
#
# Returns $true if above conditions are met otherwise $false
#
#  NOTES:  Value compare is not deep compare

function Compare-Hashes{
    param (
        [hashtable] $hash1,
        [hashtable] $hash2
    )

    $compare = $true
    foreach ($key in $hash1.keys) {
        if ( -Not ( $hash2.ContainsKey($key ))) {
            Write-Host("1st hash key {0} not in 2nd hash" -f $key )
            $compare = $false
        }
    }
    foreach ($key in $hash2.keys) { 
        if ( -Not ( $hash1.ContainsKey($key ))) {
            Write-Host("2nd hash key {0} not in 1st hash" -f $key )
            $compare = $false
        }
    }
    if ($compare) {
        foreach ($key in $hash1.keys )
        {
            # Compare object is true ( non null if miscompare )
            if ( Compare-Object $hash1.$key $hash2.$key ) {
                Write-Host("key {0} values differ {1} and {2}" -f $key, $hash1.$key, $hash2.$key )
                $compare = $false
            }
        }
    }
    return $compare
}

