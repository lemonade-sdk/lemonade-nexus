function(create_project project_name)
	if(NOT MSVC)
		if(NOT TARGET all_projects)
			add_custom_target(all_projects)
		endif()
	endif()

	cmake_parse_arguments(PARSE_ARGV 1 arg "LIB_ONLY" "" "DEPENDENCIES")

	file(GLOB_RECURSE source_files "${CMAKE_CURRENT_SOURCE_DIR}/src/*.[c|h]pp")
	file(GLOB_RECURSE include_files "${CMAKE_CURRENT_SOURCE_DIR}/include/*.[c|h]pp")
	list(REMOVE_ITEM source_files "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")

	# On Apple, also pick up Objective-C++ (.mm) source files
	if(APPLE)
		file(GLOB_RECURSE objcxx_source_files "${CMAKE_CURRENT_SOURCE_DIR}/src/*.mm")
		# Don't include main.mm here — it's handled separately below
		list(REMOVE_ITEM objcxx_source_files "${CMAKE_CURRENT_SOURCE_DIR}/src/main.mm")
		list(APPEND source_files ${objcxx_source_files})
	endif()

	if(NOT source_files STREQUAL "")
		add_library(${project_name} ${source_files} ${include_files})
		target_compile_features(${project_name} PUBLIC cxx_std_20)
		target_include_directories(${project_name} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
		target_include_directories(${project_name} PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/include")
		target_link_libraries(${project_name} PUBLIC ${arg_DEPENDENCIES})
		set_target_properties(${project_name} PROPERTIES EXPORT_COMPILE_COMMANDS ON)

		if(NOT MSVC)
			add_dependencies(all_projects ${project_name})
		endif()
	endif()

	if(NOT arg_LIB_ONLY)
		add_executable("${project_name}App" ${source_files} ${include_files})
		target_compile_features("${project_name}App" PUBLIC cxx_std_20)
		target_include_directories("${project_name}App" PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
		target_include_directories("${project_name}App" PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/include")
		target_link_libraries("${project_name}App" PUBLIC ${arg_DEPENDENCIES})
		set_target_properties("${project_name}App" PROPERTIES EXPORT_COMPILE_COMMANDS ON)

		if(TARGET ${project_name})
			target_link_libraries("${project_name}App" PRIVATE ${project_name})
		endif()

		if(NOT MSVC)
			add_dependencies(all_projects "${project_name}App")
		endif()

		if(APPLE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.mm")
			target_sources("${project_name}App" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/main.mm")
		else()
			target_sources("${project_name}App" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
		endif()
	endif()
endfunction()
