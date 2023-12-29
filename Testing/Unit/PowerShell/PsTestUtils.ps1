# $hash1 = @{
#     "color" = "blue"
#     "city" = "boston"
#     "team" = "redsox"
# }

# $hash2 = $hash1.clone()

# $hash3 = $hash1.clone()

# $hash2.color = "red"

# $hash1keys=$hash1.keys

# foreach ($h in $hash1keys ) {
#     Write-Host "${h}: $($hash1.$h)"
# }
function Compare-Hashes{
    param (
        [hashtable] $hash1,
        [hashtable] $hash2
    )

    $compare = $true

    $arr1 = @()
    $arr2 = @()

    foreach ($key in $hash1.keys){ $arr1 += $key }
    foreach ($key in $hash2.keys){ $arr2 += $key }

    foreach ($key in $arr1) {
        if ( -Not ( $hash2.ContainsKey($key ))) {
            Write-Output("1st hash key {0} not in 2nd hash" -f $key )
            $compare = $false
        }
    }
    foreach ($key in $arr2) { 
        if ( -Not ( $hash1.ContainsKey($key ))) {
            Write-Output("2nd hash key {0} not in 1st hash" -f $key )
            $compare = $false
        }
    }
    if ($compare) {
        foreach ($key in $arr1 )
        {
            if ( -Not ( $hash1.$key -eq $hash2.$key )) {
                Write-Output("key {0} values differ {1} and {2}" -f $key, $hash1.$key, $hash2.$key )
                $compare = $false
            }
        }
    }
    $compare
}

