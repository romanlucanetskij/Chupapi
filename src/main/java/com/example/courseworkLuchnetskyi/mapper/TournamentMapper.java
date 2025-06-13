package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.TournamentRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.model.Tournament;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(componentModel = "spring")
public interface TournamentMapper {
    Tournament toEntity(TournamentRequestDto request);
    TournamentResponseDto toDto(Tournament tournament);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateTournamentFromRequest(@MappingTarget Tournament tournament, TournamentRequestDto request);
}
