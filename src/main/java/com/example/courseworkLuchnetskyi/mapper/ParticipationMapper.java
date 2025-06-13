package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.ParticipationResponseDto;
import com.example.courseworkLuchnetskyi.model.Participation;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface ParticipationMapper {

    @Mapping(target = "team", ignore = true)
    @Mapping(target = "tournament", ignore = true)
    Participation toEntity(ParticipationRequestDto dto);

    ParticipationResponseDto toDto(Participation participation);
}
