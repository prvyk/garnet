﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using Garnet.common;

namespace Garnet.server
{
    public class ModuleUtils
    {
        /// <summary>
        /// Load assemblies from specified binary paths
        /// </summary>
        /// <param name="binaryPaths">Source paths for assemblies (can be either files or directories)</param>
        /// <param name="allowedExtensionPaths">List of allowed paths for loading assemblies from</param>
        /// <param name="allowUnsignedAssemblies">True if loading unsigned assemblies is allowed</param>
        /// <param name="loadedAssemblies">Loaded assemblies</param>
        /// <param name="errorMessage">Error message</param>
        /// <param name="ignoreFileNames">File names to ignore (optional)</param>
        /// <param name="searchOption">In case path is a directory, determines whether to search only top directory or all subdirectories</param>
        /// <param name="ignoreAssemblyLoadErrors">False if method should return an error when at least one assembly was not loaded correctly (false by default)</param>
        /// <param name="ignorePathCheckWhenUndefined">Ignore path check when path is undefined (default false).</param>
        /// <returns></returns>
        public static bool LoadAssemblies(
            IEnumerable<string> binaryPaths,
            string[] allowedExtensionPaths,
            bool allowUnsignedAssemblies,
            out IEnumerable<Assembly> loadedAssemblies,
            out ReadOnlySpan<byte> errorMessage,
            string[] ignoreFileNames = null,
            SearchOption searchOption = SearchOption.AllDirectories,
            bool ignoreAssemblyLoadErrors = false,
            bool ignorePathCheckWhenUndefined = false)
        {
            loadedAssemblies = null;
            errorMessage = default;

            // Get all binary file paths from inputs binary paths
            if (!FileUtils.TryGetFiles(binaryPaths, out var binaryFiles, out _, [".dll", ".exe"], ignoreFileNames, SearchOption.AllDirectories))
            {
                errorMessage = CmdStrings.RESP_ERR_GENERIC_GETTING_BINARY_FILES;
                return false;
            }

            if ((allowedExtensionPaths == null) && !ignorePathCheckWhenUndefined)
            {
                errorMessage = CmdStrings.RESP_ERR_GENERIC_MUST_DEFINE_ASSEMBLY_BINPATH;
                return false;
            }
            // Check that all binary files are contained in allowed binary paths
            else if (allowedExtensionPaths != null)
            {
                if (binaryFiles.Any(f =>
                        allowedExtensionPaths.All(p => !FileUtils.IsFileInDirectory(f, p))))
                {
                    errorMessage = CmdStrings.RESP_ERR_GENERIC_BINARY_FILES_NOT_IN_ALLOWED_PATHS;
                    return false;
                }
            }

            // If necessary, check that all assemblies are digitally signed
            if (!allowUnsignedAssemblies)
            {
                foreach (var filePath in binaryFiles)
                {
                    try
                    {
                        var isSigned = false;

                        using var fs = File.OpenRead(filePath);
                        using var peReader = new PEReader(fs);

                        if (peReader.HasMetadata)
                        {
                            var metadataReader = peReader.GetMetadataReader();
                            var assemblyPublicKeyHandle = metadataReader.GetAssemblyDefinition().PublicKey;

                            isSigned = !assemblyPublicKeyHandle.IsNil &&
                                       metadataReader.GetBlobBytes(assemblyPublicKeyHandle).Length > 0;
                        }

                        if (!isSigned)
                        {
                            errorMessage = CmdStrings.RESP_ERR_GENERIC_ASSEMBLY_NOT_SIGNED;
                            return false;
                        }
                    }
                    catch (Exception)
                    {
                        errorMessage = CmdStrings.RESP_ERR_GENERIC_ACCESSING_ASSEMBLIES;
                        return false;
                    }
                }
            }

            // Get all assemblies from binary files
            if (!FileUtils.TryLoadAssemblies(binaryFiles, out loadedAssemblies, out _) && !ignoreAssemblyLoadErrors)
            {
                errorMessage = CmdStrings.RESP_ERR_GENERIC_LOADING_ASSEMBLIES;
                return false;
            }

            return true;
        }
    }
}