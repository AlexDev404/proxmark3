file(REMOVE_RECURSE
  "libnxpsc.a"
  "libnxpsc.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/nxpsc.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
